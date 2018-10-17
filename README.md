# AwsCognitoNode
A Node.js based solution for authenticating user with integration of AWS cognito
First of all you need to create your account in AWS and then create User pool
Steps to create user pool are as follows

1) Go to the Amazon Cognito console. You might be prompted for your AWS credentials.

2) Choose Manage your User Pools.

3) In the top-right corner of the page, choose Create a User Pool.

4) Provide a name for your user pool, and choose Review Defaults to save the name.

5) On the Attributes page, choose Email address or phone number and Allow email addresses.

6) At the bottom of the page, choose Next Step to save the attribute.

7) On the navigation bar on the left-side of the page, choose Review.

8) On the bottom of the Review page, choose Create pool.

Once the setup is done all you need is to save the userPoolId and clientId as they are required for authenticating the user against
your userpool created.

In Node server , we have few API's 
1) Home (localhost:3000) : It is accesible to every user without any authentication
2) Sign up (localhost:3000/signUp) : post request type where in body you need to pass all the attribute which are marked as mandatary while Userpool account creation
3) Sign In (localhost:3000/signIn) : enter email and password for authentication
4) Get book (localhost:3000/book) : This API will return data to authorized user only else 
this api will return 403 forbidden if you haven't signIn to the application 
