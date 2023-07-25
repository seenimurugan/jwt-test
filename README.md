# Getting Started

### Prerequisites

jwt-poc app needs up and running to view the ebl, the url for the jwt-poc app can be passed using the UI form.

### Details

* Fill in the User, Ebl & Token details @  http://localhost:8081
  * Rsa Key pair from static file is loaded and autofilled on the UI form. User can also pass their own Key pair in JWK format. 
  * Key pair in JWK format can also be generated from here https://mkjwk.org/. Key pair set needs to contain both private and public key. 
  * User needs to provide 2 sets of Key pair. One for Access token generation and another for Data token generation.
* When form submitted the code generates 2 types of JWT token 1. header token(access_token) 2. body token(user & ebl details)
* Click 'Show EBL' button to view the ebl. Both JWT tokens are sent to Galileo app for authentication and once authenticated it redirects to ebl page. 



