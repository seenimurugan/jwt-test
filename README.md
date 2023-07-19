# Getting Started

### Prerequisites

jwt-poc app needs up and running to view the ebl, the url for the jwt-poc app can be passed using the UI form.

### Details

* Fill in the User, Ebl, Token details by accessing  http://localhost:8081
  * New Key pair generated on every visit to home page and autofilled on the UI form. User can also pass their own Key pair in JWK format. 
  * Key pair in JWK format can also be generated from here https://mkjwk.org/. Key pair set needs to contain both private and public key. 
  * User needs to provide 2 sets of Key pair. One for Header token generation and another for body token generation.
* When submitted 2 types of JWT token generated 1. header token(access_token) 2. body token(user, ebl details)
* Click 'Ebl Details' button to view the ebl. Both JWT tokens are sent to Galileo app for authentication, once authenticated it redirects to ebl page. 



