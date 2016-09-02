var fs = require("fs");
var email = require("emailjs/email");
var Aes = require('./crypto/aes.js');
Aes.Ctr = require('./crypto/aes-ctr.js');
var sha1 = require('./crypto/sha1.js');
var datastorage = false;
var servicelog = false;

var globalSalt = sha1.hash(JSON.stringify(new Date().getTime()));

function setStatustoClient(cookie, status) {
    var sendable = { type: "statusData",
		     content: status };
    cookie.connection.send(JSON.stringify(sendable));
}

function sendPlainTextToClient(cookie, sendable) {
    cookie.connection.send(JSON.stringify(sendable));
}

function sendCipherTextToClient(cookie, sendable) {
    var cipherSendable = { type: sendable.type,
			   content: Aes.Ctr.encrypt(JSON.stringify(sendable.content),
						    cookie.aesKey, 128) };
    cookie.connection.send(JSON.stringify(cipherSendable));
}

function generateEmailToken(email) {
    return { mail: sha1.hash(email).slice(0, 8),
	     key: sha1.hash(globalSalt + JSON.stringify(new Date().getTime())).slice(0, 16) };
}

function getNewChallenge() {
    return ("challenge_" + sha1.hash(globalSalt + new Date().getTime().toString()) + "1");
}

function stateIs(cookie, state) {
    return (cookie.state === state);
}

function setState(cookie, state) {
    cookie.state = state;
}

function processClientStarted(cookie) {
    if(cookie["user"] !== undefined) {
	if(cookie.user["username"] !== undefined) {
	    servicelog("User " + cookie.user.username + " logged out");
	}
    }
    servicelog("Sending initial login view to client #" + cookie.count);
    setState(cookie, "clientStarted");
    cookie.aesKey = "";
    cookie.user = {};
    cookie.challenge = "";
    var sendable = { type: "loginView" }
    sendPlainTextToClient(cookie, sendable);
    setStatustoClient(cookie, "Login");
}

function processUserLogin(cookie, content) {
    var sendable;
    if(!content.username) {
	servicelog("Illegal user login message");
	processClientStarted(cookie);
	return;
    } else {
	var user = getUserByHashedName(content.username);
	if(user.length === 0) {
	    servicelog("Unknown user login attempt");
	    processClientStarted(cookie);
	    return;
	} else {
	    cookie.user = user[0];
	    cookie.aesKey = user[0].password;
	    servicelog("User " + user[0].username + " logging in");
	    var plainChallenge = getNewChallenge();
	    servicelog("plainChallenge:   " + plainChallenge);
	    cookie.challenge = JSON.stringify(plainChallenge);
	    sendable = { type: "loginChallenge",
			 content: plainChallenge };
	    sendCipherTextToClient(cookie, sendable);
	}
    }
}

function processCreateAccount(cookie, accountDefaults, content) {
    var sendable;
    var language =  datastorage.read("main").main.language;
    var siteFullUrl =  datastorage.read("main").main.siteFullUrl;
    var adminEmailAddess = datastorage.read("main").main.adminEmailAddess;
    servicelog("temp passwd: " + JSON.stringify(cookie.aesKey));
    var account = JSON.parse(Aes.Ctr.decrypt(content, cookie.aesKey, 128));

    if(typeof(account) !== "object") {
	servicelog("Received illegal account creation data");
	return false;
    }
    if(account["username"] === undefined) {
	servicelog("Received account creation data without username");
	return false;
    }

    if(stateIs(cookie, "newUserValidated")) {
	servicelog("Request for new user: [" + account.username + "]");
	if(!createAccount(account, accountDefaults)) {
	    servicelog("Cannot create account " + account.username);
	    // there are more possible reasons than already existing account, however user needs
	    // not know about that, hence display only "Account already exists!" in client...
	    setStatustoClient(cookie, "Account already exists!");
	    sendable = { type: "createNewAccount" };
	    sendPlainTextToClient(cookie, sendable);
	    return;
	} else {
	    processClientStarted(cookie);
	    setStatustoClient(cookie, "Account created!");
	    var emailSubject = getLanguageText(language, "NEW_ACCOUNT_CONFIRM_SUBJECT");
	    var emailAdminSubject = getLanguageText(language, "NEW_ACCOUNT_CONFIRM_ADMIN_SUBJECT");
	    var emailBody = fillTagsInText(getLanguageText(language,
							   "NEW_ACCOUNT_CONFIRM_GREETING"),
					   account.username,
					   siteFullUrl);
	    var emailAdminBody = fillTagsInText(getLanguageText(language,
								"NEW_ACCOUNT_CONFIRM_ADMIN_GREETING"),
						account.username);
	    sendEmail(cookie, emailSubject, emailBody, account.email, "account creation");
	    sendEmail(cookie, emailAdminSubject, emailAdminBody, adminEmailAddess, "account creation");
	    return;
	}
    }
    if(stateIs(cookie, "oldUserValidated")) {
	servicelog("Request account change for user: [" + account.username + "]");
	var user = getUserByUserName(account.username);
	if(user.length === 0) {
	    processClientStarted(cookie);
	    setStatustoClient(cookie, "Illegal user operation!");
	    return;
	} else {
	    if(updateUserAccount(cookie, account)) {
		setStatustoClient(cookie, "Account updated!");
	    } else {
		setStatustoClient(cookie, "Account update failed!");
	    }
	    processClientStarted(cookie);
	    return;
	}
    }
}

function processConfirmEmail(cookie, content) {
    servicelog("Request for email verification: [" + content + "]");
    sendVerificationEmail(cookie, content);
    processClientStarted(cookie);
    setStatustoClient(cookie, "Email sent!");
}

function processValidateAccount(cookie, content) {
    if(!content.email || !content.challenge) {
	servicelog("Illegal validate account message");
	processClientStarted(cookie);
	return;
    } else {
	servicelog("Validation code: " + JSON.stringify(content));
	account = validateAccountCode(content.email.toString());
	if((account !== false) && (Aes.Ctr.decrypt(content.challenge, account.token.key, 128)
				   === "clientValidating")) {
	    setState(cookie, "newUserValidated");
	    setStatustoClient(cookie, "Validation code correct!");
	    cookie.aesKey = account.token.key;
	    var newAccount = {email: account.email};
	    newAccount.buttonText = "Create Account!";
	    var user = getUserByEmail(account.email);
	    if(user.length !== 0) {
		newAccount.username = user[0].username;
		newAccount.realname = user[0].realname;
		newAccount.phone = user[0].phone;
		newAccount.buttonText = "Save Account!"
		setState(cookie, "oldUserValidated");
	    }
	    sendable = { type: "createNewAccount",
			 content: newAccount };
	    sendCipherTextToClient(cookie, sendable);
	    return;
	} else {
	    processClientStarted(cookie);
	    setStatustoClient(cookie, "Validation code failed!");
	    return;
	}
    }
}

function sendVerificationEmail(cookie, recipientAddress) {
    var language =  datastorage.read("main").main.language;
    removePendingRequest(cookie, recipientAddress);
    var pendingData = datastorage.read("pending");
    var emailData = datastorage.read("email");
    var timeout = new Date();
    var emailToken = generateEmailToken(recipientAddress);
    timeout.setHours(timeout.getHours() + 24);
    var request = { email: recipientAddress,
		    token: emailToken,
		    date: timeout.getTime() };
    pendingData.pending.push(request);
    if(datastorage.write("pending", pendingData) === false) {
	servicelog("Pending database write failed");
    }
    if(getUserByEmail(recipientAddress).length === 0) {
	var emailSubject = getLanguageText(language, "NEW_ACCOUNT_REQUEST_SUBJECT");
	var emailBody = fillTagsInText(getLanguageText(language,
						       "NEW_ACCOUNT_REQUEST_GREETING"),
				       (request.token.mail + request.token.key));
    } else {
	var emailSubject = getLanguageText(language, "PASSWORD_RESET_SUBJECT");
	var emailBody = fillTagsInText(getLanguageText(language,
						       "PASSWORD_RESET_GREETING"),
				       getUserByEmail(recipientAddress)[0].username,
				       (request.token.mail + request.token.key));
    }
    sendEmail(cookie, emailSubject, emailBody, recipientAddress, "account verification");
}

function readUserData() {
    userData = datastorage.read("users");
    if(userData === false) {
	servicelog("User database read failed");
    } 
    return userData;
}

function updateUserAccount(cookie, account) {
    var userData = readUserData();
    var oldUserAccount = getUserByUserName(account.username);
    var language =  datastorage.read("main").main.language;
    var siteFullUrl =  datastorage.read("main").main.siteFullUrl;
    var adminEmailAddess = datastorage.read("main").main.adminEmailAddess;
    if(oldUserAccount.length === 0) {
	return false;
    } else {
	var newUserData = { users : [] };
	newUserData.users = userData.users.filter(function(u) {
	    return u.username !== account.username;
	});
	var newUserAccount = { username: account.username,
			       hash: sha1.hash(account.username),
			       password: account.password,
			       applicationData: oldUserAccount[0].applicationData };
	if(account["realname"] !== undefined) { newUserAccount.realname = account.realname; }
	if(account["email"] !== undefined) { newUserAccount.email = account.email; }
	if(account["phone"] !== undefined) { newUserAccount.phone = account.phone; }
	newUserData.users.push(newUserAccount);
	if(datastorage.write("users", newUserData) === false) {
	    servicelog("User database write failed");
	} else {
	    servicelog("Updated User Account: " + JSON.stringify(newUserAccount));
	}
	var emailSubject = getLanguageText(language, "PASSWORD_RESET_CONFIRM_SUBJECT");
	var emailAdminSubject = getLanguageText(language, "PASSWORD_RESET_CONFIRM_ADMIN_SUBJECT");
	var emailBody = fillTagsInText(getLanguageText(language,
						       "PASSWORD_RESET_CONFIRM_GREETING"),
				       account.username,
				       siteFullUrl);
	var emailAdminBody = fillTagsInText(getLanguageText(language,
							    "PASSWORD_RESET_CONFIRM_ADMIN_GREETING"),
					    account.username);
	sendEmail(cookie, emailSubject, emailBody, account.email, "account update");
	sendEmail(cookie, emailAdminSubject, emailAdminBody, adminEmailAddess, "account update");
	return true;
    }
}

function getUserByUserName(username) {
    return readUserData().users.filter(function(u) {
	return u.username === username;
    });
}

function getUserByEmail(email) {
    return readUserData().users.filter(function(u) {
	return u.email === email;
    });
}

function getUserByHashedName(hash) {
    return readUserData().users.filter(function(u) {
	return u.hash === hash;
    });
}

function createAccount(account, accountDefaults) {
    if(account["password"] === undefined) {
	servicelog("Received account creation data without password");
	return false;
    }
    var userData = readUserData();
    if(userData.users.filter(function(u) {
	return u.username === account.username;
    }).length !== 0) {
	servicelog("Cannot create an existing user account");
	return false;
    } else {
	var newAccount = { username: account.username,
			   hash: sha1.hash(account.username),
			   password: account.password,
			   applicationData: accountDefaults };
	if(account["realname"] !== undefined) { newAccount.realname = account.realname; }
	if(account["email"] !== undefined) { newAccount.email = account.email; }
	if(account["phone"] !== undefined) { newAccount.phone = account.phone; }
	userData.users.push(newAccount);
	if(datastorage.write("users", userData) === false) {
	    servicelog("User database write failed");
	    return false;
	} else {
	    return true;
	}
    }
}

function validateAccountCode(code) {
    var userData = datastorage.read("pending");
    if(Object.keys(userData.pending).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return false;
    }
    var target = userData.pending.filter(function(u) {
	return u.token.mail === code.slice(0, 8);
    });
    if(target.length === 0) {
	return false;
    } else {
	var newUserData = { pending : [] };
	newUserData.pending = userData.pending.filter(function(u) {
	    return u.token.mail !== code.slice(0, 8);
	});

	if(datastorage.write("pending", newUserData) === false) {
	    servicelog("Pending requests database write failed");
	} else {
	    servicelog("Removed pending request from database");
	}
	return target[0];
    }
}

function removePendingRequest(cookie, emailAdress) {
    var userData = datastorage.read("pending");
    if(Object.keys(userData.pending).length === 0) {
	servicelog("Empty pending requests database, bailing out");
	return;
    }
    if(userData.pending.filter(function(u) {
	return u.email === emailAdress;
    }).length !== 0) {
	servicelog("Removing duplicate entry from pending database");
	var newUserData = { pending : [] };
	newUserData.pending = userData.pending.filter(function(u) {
	    return u.email !== emailAdress;
	});
	if(datastorage.write("pending", newUserData) === false) {
	    servicelog("Pending requests database write failed");
	}
    } else {
	servicelog("no duplicate entries in pending database");
    }
}

function sendEmail(cookie, emailSubject, emailBody, recipientAddress, logline) {
    var emailData = datastorage.read("email");
    if(emailData.blindlyTrust) {
	servicelog("Trusting self-signed certificates");
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    }
    email.server.connect({
	user: emailData.user,
	password: emailData.password,
	host: emailData.host,
	ssl: emailData.ssl
    }).send({ text: emailBody,
	      from: emailData.sender,
	      to: recipientAddress,
	      subject: emailSubject }, function(err, message) {
		  if(err) {
		      servicelog(err + " : " + JSON.stringify(message));
		      setStatustoClient(cookie, "Failed sending email!");
		  } else {
		      servicelog("Sent " + logline + " email to " + recipientAddress);
		      setStatustoClient(cookie, "Sent email");
		  }
	      });
}

setInterval(function() {
    var now = new Date().getTime();
    var userData = datastorage.read("pending");
    if(Object.keys(userData.pending).length === 0) {
	servicelog("No pending requests to purge");
	return;
    }
    
    var purgeCount = 0
    var newUserData = { pending : [] };
    userData.pending.forEach(function(r) {
	if(r.date < now) {
	    purgeCount++;
	} else {
	    newUserData.pending.push(r);
	}
    });

    if(purgeCount === 0) {
	servicelog("No pending requests timeouted");
	return;
    } else {
	if(datastorage.write("pending", newUserData) === false) {
	    servicelog("Pending requests database write failed");
	} else {
	    servicelog("Removed " + purgeCount + " timeouted pending requests");
	}
    }
}, 1000*60*60);

function getLanguageText(language, tag) {
    var langData = datastorage.read("language");
    var langIndex = langData.language.indexOf(language);
    if(++langIndex === 0) { return false; }
    if(langData.substitution.filter(function(f) { return f.tag === tag }).length === 0) { return false; }
    return langData.substitution.filter(function(f) { return f.tag === tag })[0]["LANG" + langIndex];
}

function fillTagsInText(text) {
    for(var i = 1; i < arguments.length; i++) {
	var substituteString = "_SUBSTITUTE_TEXT_" + i + "_";
	text = text.replace(substituteString, arguments[i]);
    }
    return text;
}

function initialize(ds, sl) {
    datastorage = ds;
    servicelog = sl;
    servicelog("initialized userauth module");
    datastorage.initialize("pending", { pending : [] }, true);

}

function getClientBody() {
    var clientbody = fs.readFileSync("./userauth/client.js", "utf8");
    var aesjs = fs.readFileSync("./userauth/crypto/aes.js", "utf8");
    var aesctrjs = fs.readFileSync("./userauth/crypto/aes-ctr.js", "utf8");
    var sha1js = fs.readFileSync("./userauth/crypto/sha1.js", "utf8");
    return clientbody + aesjs + aesctrjs + sha1js;
}

function decrypt(content, cookie) {
    return Aes.Ctr.decrypt(content, cookie.user.password, 128);
}

// --------------

module.exports.initialize = initialize;
module.exports.getClientBody = getClientBody;
module.exports.decrypt = decrypt;
module.exports.processClientStarted = processClientStarted;
module.exports.processUserLogin = processUserLogin;
module.exports.processCreateAccount = processCreateAccount;
module.exports.processConfirmEmail = processConfirmEmail;
module.exports.processValidateAccount = processValidateAccount;
module.exports.stateIs = stateIs;
module.exports.setState = setState;
module.exports.setStatustoClient = setStatustoClient;
module.exports.getLanguageText = getLanguageText;
module.exports.sendCipherTextToClient = sendCipherTextToClient;
module.exports.getLanguageText = getLanguageText;
module.exports.fillTagsInText = fillTagsInText;
module.exports.getUserByEmail = getUserByEmail;
module.exports.getUserByUserName = getUserByUserName;
module.exports.sendEmail = sendEmail;
