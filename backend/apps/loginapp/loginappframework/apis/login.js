/**
 * Logs a user in. 
 * (C) 2015 TekMonks. All rights reserved.
 */
const utils = require(`${CONSTANTS.LIBDIR}/utils.js`);
const totp = require(`${APP_CONSTANTS.LIB_DIR}/totp.js`);
const userid = require(`${APP_CONSTANTS.LIB_DIR}/userid.js`);
const register = require(`${APP_CONSTANTS.API_DIR}/register.js`);
const jwttokenmanager = APIREGISTRY.getExtension("JWTTokenManager");
const queueExecutor = require(`${CONSTANTS.LIBDIR}/queueExecutor.js`);

const DEFAULT_QUEUE_DELAY = 500, LOGIN_LISTENERS_MEMORY_KEY = "__org_monkshu_loginapp_login_listeners", 
	LOGINS_MEMORY_KEY = "__org_monkshu_loginapp_logins", REASONS = { BAD_PASSWORD: "badpw", BAD_ID: "badid", 
		BAD_OTP: "badotp", BAD_APPROVAL: "notapproved", OK: "allok", UNKNOWN: "unknown", DOMAIN_ERROR: "domainerror" };

exports.init = _ => {
	jwttokenmanager.addListener((event, object) => {
		if (event == "token_generated") try {
			const token = ("Bearer "+object.token).toLowerCase(); 
			const logins = CLUSTER_MEMORY.get(LOGINS_MEMORY_KEY) || {};
			logins[token] = {id: object.response.id, org: object.response.org, name: object.response.name, role: object.response.role}; 
			CLUSTER_MEMORY.set(LOGINS_MEMORY_KEY, logins);
		} catch (err) {LOG.error(`Could not init home for the user with ID ${object.response.id}, name ${object.response.name}, error was: ${err}`);}

		if (event == "token_expired") {
			const logins = CLUSTER_MEMORY.get(LOGINS_MEMORY_KEY) || {};
			const token = ("Bearer "+object.token).toLowerCase();
			delete logins[token]; CLUSTER_MEMORY.set(LOGINS_MEMORY_KEY, logins);
		}
	});
}

exports.addLoginListener = (modulePath, functionName) => {
	const loginlisteners = CLUSTER_MEMORY.get(LOGIN_LISTENERS_MEMORY_KEY, []);
	loginlisteners.push({modulePath, functionName});
	CLUSTER_MEMORY.set(LOGIN_LISTENERS_MEMORY_KEY, loginlisteners);
}

exports.doService = async (jsonReq, servObject) => {
	if (!validateRequest(jsonReq)) {LOG.error("Validation failure."); return CONSTANTS.FALSE_RESULT;}
	
	LOG.debug(`Got login request for ID ${jsonReq.id}`);

	if (!(await register.shouldAllowDomain(jsonReq, "id"))) {	// domain is not allowed, don't check anything else
		LOG.error(`Unable to login: ${jsonReq.name}, ID: ${jsonReq.id}, domain is not allowed.`);
		return {...CONSTANTS.FALSE_RESULT, reason: REASONS.DOMAIN_ERROR};
	}

	const result = await userid.checkPWPH(jsonReq.id, jsonReq.pwph); 

	result.tokenflag = false; 	// default assume login failed no JWT token will be generated
	if (result.result && result.approved) {	// perform second factor
		//dma flag is to disable mutifactor authentication
		if (jsonReq?.dma === true || result.totpsec === APP_CONSTANTS.TOTP_BYPASS_FLAG) { result.result = true; result.tokenflag = true; result.reason = REASONS.OK;
			LOG.info(`User ${result.id} logged in with MFA bypassed.`);
		} else {
		result.result = totp.verifyTOTP(result.totpsec, jsonReq.otp); 
		if (!result.result) {LOG.error(`Bad OTP given for: ${result.id}.`); result.reason = REASONS.BAD_OTP;}
		else {result.tokenflag = true; result.reason = REASONS.OK;}	// ID is OK, password is OK, OTP is OK, and user is approved
		}
	} else if (result.result && (!result.approved)) {LOG.info(`User not approved, ${result.id}.`); result.reason = REASONS.BAD_APPROVAL;}
	else {
		result.reason = result.reason == userid.NO_ID ? REASONS.BAD_ID : result.reason == userid.BAD_PASSWORD ? REASONS.BAD_PASSWORD : REASONS.UNKNOWN;
		LOG.error(`${result.reason == REASONS.BAD_ID?"Bad id":result.reason == REASONS.BAD_PASSWORD?"Bad password":"Unknown reason for login failure"} for login request for ID: ${jsonReq.id}.`);
	}

	const keysBeforeListeners = Object.keys(result);	// anything a listener adds below is meant for the UI, so it is returned
	if (result.tokenflag && (!(await _informLoginListeners(result)))) {	// inform login listeners and give them a chance to veto the login
		result.tokenflag = false; result.result = false;
		if (result.reason == REASONS.OK || (!result.reason)) result.reason = REASONS.UNKNOWN;	// if the listener didn't add a reason for veto, then make the reason unknown
	}

	if (result.tokenflag) {	// tokenflag means generate JWT, meaning login succeeded
		LOG.info(`User logged in: ${result.id}${APP_CONSTANTS.CONF.verify_email_on_registeration?`, email verification status is ${result.verified}.`:"."}`); 
		const remoteIP = utils.getClientIP(servObject.req);	// api end closes the socket so when the queue task runs remote IP is lost.
		queueExecutor.add(async _=>{	// update login stats don't care much if it fails
			try { await userid.updateLoginStats(jsonReq.id, Date.now(), remoteIP); }
			catch(err) {LOG.error(`Error updating login stats for ID ${jsonReq.id}. Error is ${err}.`);}
		}, undefined, true, APP_CONSTANTS.CONF.login_update_delay||DEFAULT_QUEUE_DELAY);
	} else LOG.error(`Bad login or not approved for ID: ${jsonReq.id}.`);

	if (!result.tokenflag) return {result: false, reason: result.reason};

	const listenerAdditions = Object.fromEntries(Object.entries(result).filter(([key]) => !keysBeforeListeners.includes(key)));
	return {result: true, tokenflag: true, id: result.id, name: result.name, org: result.org,domain: result.domain, role: result.role, totpsec: result.totpsec, verified: result.verified==1?true:false, ...listenerAdditions};
}

exports.getID = headers => {
	if (!headers["authorization"]) return null; const logins = CLUSTER_MEMORY.get(LOGINS_MEMORY_KEY) || {};
	return logins[headers["authorization"].toLowerCase()]?logins[headers["authorization"].toLowerCase()].id:null;
}

exports.getOrg = headers => {
	if (!headers["authorization"]) return null; const logins = CLUSTER_MEMORY.get(LOGINS_MEMORY_KEY) || {};
	return logins[headers["authorization"].toLowerCase()]?logins[headers["authorization"].toLowerCase()].org:null;
}

exports.getKey = headers => APIREGISTRY.getExtension("apikeychecker").getIncomingAPIKey(headers);

exports.getOrgKeys = async headersOrOrg => {
	const orgIn = typeof headersOrOrg == "string" ? headersOrOrg : exports.getOrg(headersOrOrg);
	return await userid.getKeysForOrg(orgIn);
}

exports.setOrgKeys = async (headersOrOrg, keys) => {
	const orgIn = typeof headersOrOrg == "string" ? headersOrOrg : exports.getOrg(headersOrOrg);
	return await userid.setKeysForOrg(keys, orgIn);
}

exports.getRole = headers => {
	if (!headers["authorization"]) return null;
	const logins = CLUSTER_MEMORY.get(LOGINS_MEMORY_KEY) || {};
	return logins[headers["authorization"].toLowerCase()]?logins[headers["authorization"].toLowerCase()].role:null;
}

exports.isAdmin = headers => (exports.getRole(headers))?.toLowerCase() == APP_CONSTANTS.ROLES.ADMIN.toLowerCase();

exports.isIDAdminForOrg = async (id, org) => {
	const adminsForOrg = await userid.getAdminsForOrgOrSuborg(org); 
	if (adminsForOrg && adminsForOrg.includes(id)) return true; else return false;
}

exports.REASONS = REASONS;

const _informLoginListeners = async result => {
	const loginlisteners = CLUSTER_MEMORY.get(LOGIN_LISTENERS_MEMORY_KEY, []);
	for (const listener of loginlisteners) {
		const listenerFunction = require(listener.modulePath)[listener.functionName];
        const listenerFunctionResult = await listenerFunction(result);
		if (!listenerFunctionResult) return false; 
	}
    return true;
}

const validateRequest = jsonReq => jsonReq && jsonReq.pwph && jsonReq.id && (jsonReq?.dma === true || jsonReq.otp !== undefined);