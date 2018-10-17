var express = require('express');
var AWS = require("aws-sdk");
var bodyParser = require("body-parser");  
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
//const AWS = require('aws-sdk');
const request = require('request');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
global.fetch = require('node-fetch');

const region = 'us-east-2';
//const CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;

//credential need to be store in seperate files as they are private info
var poolData = {
    UserPoolId : 'us-east-2_VokcKSnuQ', // your user pool id here
    ClientId : '2fr0lsq25p23lu9vusr1qkd4nr' // your app client id here
};
var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
var iss = 'https://cognito-idp.' + region + '.amazonaws.com/' + poolData.UserPoolId;
var pems;

var app = express();

//You need to use bodyParser() if you want the form data to be available in req.body.
app.use(bodyParser.json());  
//simple home page URL
app.get('/', function (req, res) {
  res.send('Hello World!');
});

//SIgn up API
app.post('/signUp', function (req, res) {
      RegisterUser(req.body); 
      res.send('Sign Up done!');
});
app.post('/userSignInConfirm', function (req, res) {
 
    AdminConfirmSignUp(req.body); 
res.send('Admin confirm done!');
});
// Login or sign In API 
app.post('/signIn', function (req, res) {
    console.log(req.body);
     Login(req.body,res); 

});

//Create router for getting list of books that accessible for authorized user.
app.get('/book', function(req, res) {
    let jwtToken = getToken(req.headers);
   Authenticate(jwtToken,res);
   
  });

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});

function RegisterUser(requestBody){
    var attributeList = [];
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"name",Value:requestBody.username}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"preferred_username",Value:"jay"}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"gender",Value:"male"}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"birthdate",Value:"1991-06-21"}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"email",Value:requestBody.username}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"phone_number",Value:"+5412614324321"}));
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"profile",Value:"myprofile"}));
    

    userPool.signUp(requestBody.username, requestBody.password, attributeList, null, function(err, result){
        if (err) {
            console.log(err);
            return;
        }
        cognitoUser = result.user;
        console.log('user name is ' + cognitoUser.getUsername());
    });
}

function Login(requestBody,res) {
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
        Username : requestBody.username,
        Password : requestBody.password,
    });

    var userData = {
        Username : requestBody.username,
        Pool : userPool
    };
    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
        cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
    var token = result.getAccessToken().getJwtToken();
            console.log('access token + ' + result.getAccessToken().getJwtToken());
            console.log('id token + ' + result.getIdToken().getJwtToken());
            console.log('refresh token + ' + result.getRefreshToken().getToken());
        // return the information including token as JSON
         res.json({success: true, token: 'JWT ' + token});
        },
        onFailure: function(err) {
            console.log(err);
            res.status(401).send({success: false, msg: 'Authentication failed. User not found.'});
        },

    });
}
function AdminConfirmSignUp(requestBody){
  
      var userData = {
        Username : requestBody.username,
        Pool : userPool
    };
    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.confirmRegistration(requestBody.confirmCode, true, function(err, result) {
        if (err) {
            alert(err);
            return;
        }
        console.log('call result: ' + result);
    });
 
}
function Authenticate(jwtToken,res){
    
    if (!pems) {
        console.log("try to download again");
    //Download the JWKs and save it as PEM
    request({
       url: iss + '/.well-known/jwks.json',
       json: true
     }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
            pems = {};
            var keys = body['keys'];
            for(var i = 0; i < keys.length; i++) {
                //Convert each key to PEM
                var key_id = keys[i].kid;
                var modulus = keys[i].n;
                var exponent = keys[i].e;
                var key_type = keys[i].kty;
                var jwk = { kty: key_type, n: modulus, e: exponent};
                var pem = jwkToPem(jwk);
                pems[key_id] = pem;
            }
            //Now continue with validating the token
          let isAuthenticated =  ValidateToken(pems, jwtToken);
          if (isAuthenticated) {
            return res.send('Authorized. to do anything');
        } else {
          return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }
        } else {
            //Unable to download JWKs, fail the call
              return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }
    });
    } else {
        //PEMs are already downloaded, continue with validating the token
        let isAuthenticated =  ValidateToken(pems, jwtToken);
        
        if (isAuthenticated) {
          return res.send('Authorized. to do anything');
      } else {
        return res.status(403).send({success: false, msg: 'Unauthorized.'});
      }
    };
}
function ValidateToken(pems, jwtToken) {

    var token = jwtToken;
    //Fail if the token is not jwt
    var decodedJwt = jwt.decode(token, {complete: true});
    if (!decodedJwt) {
        console.log("Not a valid JWT token");
        return false;
    }

    //Fail if token is not from your User Pool
    if (decodedJwt.payload.iss != iss) {
        console.log("invalid issuer");
        return false;
    }

    //Reject the jwt if it's not an 'Access Token'
    if (decodedJwt.payload.token_use != 'access') {
        console.log("Not an access token");
        return false;
    }

    //Get the kid from the token and retrieve corresponding PEM
    var kid = decodedJwt.header.kid;
    var pem = pems[kid];
    if (!pem) {
        console.log('Invalid access token');
        return false;
    }

    //Verify the signature of the JWT token to ensure it's really coming from your User Pool

   return jwt.verify(token, pem, { issuer: iss }, function(err, payload) {
      if(err) {
        console.log("Invalid Token.");
        return false;
      } else {
        console.log("Valid Token.");
        console.log(payload);
        return true;
      }
});
};
//Create function for parse authorization token from request headers.
getToken = function (headers) {
    if (headers && headers.authorization) {
      var parted = headers.authorization.split(' ');
      if (parted.length === 2) {
        return parted[1];
      } else {
        return null;
      }
    } else {
      return null;
    }
  };