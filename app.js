const restify = require('restify')
const xml2js = require('xml2js')
const {Pool} = require('pg')
const crypto = require('crypto')
var path = require('path');
const database = process.env.DATABASE_URL

const sqlDB = new Pool( {
  connectionString: database,
  ssl: {
    rejectUnauthorized: false
  }} )

const server = restify.createServer({
  name: 'First Delegated Auth Demo',
  version: '1.0.0',
  "ignoreTrailingSlash": true
});

server.use(restify.plugins.queryParser({mapParams: true}))
server.use(restify.plugins.fullResponse())
server.use(restify.plugins.bodyParser({maxBodySize: 2097152, mapParams: false}))


// ENSURE REQUEST TO SERVER WAS TLS ENCRYPTED
function validateRequest(req, resp, next) {

  //require https when running in heroku host, otherwise allow localhost access only
  const isHeroku = req.headers["x-forwarded-proto"] === "https" && process.env.DYNO;
  if (isHeroku || !process.env.DYNO) { // force https on remote heroku dynos
    const origin = req.header("Origin");
    resp.header("Access-Control-Allow-Origin", origin);
    resp.header("Access-Control-Allow-Methods", "POST");
    resp.header("Access-Control-Allow-Headers", req.header("Access-Control-Request-Headers"));
    return next();
  } else {
    resp.send(500, getAuthResultSOAP('false') );
    return next(false)
  }
}


// DO USER LOOKUP IN DATABASE
function handleAuthQuery(request, response, next) {

  console.log( "SOAP AUTH REQUEST RECV'D" );
  try
  {
    if( -1 != request.headers['content-type'].indexOf( '/xml' ) )
    {
      response.setHeader('Content-Type', 'text/xml')
      response.setHeader('SOAPAction', 'AuthenticationService')
      const options = {explicitArray: false, tagNameProcessors: [xml2js.processors.stripPrefix] }

      xml2js.parseString( request.body, options, (err, soapJson) => {
        if (err) {
          console.log('An error has occurred: ' + err)
          return response.send(500, getAuthResultSOAP('false') )
        }

        const username = soapJson.Envelope.Body.Authenticate.username
        const hash = crypto.createHash('sha256').update(soapJson.Envelope.Body.Authenticate.password).digest('hex')

        sqlDB.connect( function (err) {
          if( err ) {
            console.log( 'DB Connection Error: ' + err );
            return response.send(500, getAuthResultSOAP('false') )
          }
          console.log( 'SQL Database Connected. Querying for user ' + username )
          sqlDB.query( "SELECT 'found' as isfound FROM users WHERE username = $1 and passwd_hash = $2 limit 1", [username, hash] )
              .then( (result) => {
                const authResult = result.rowCount > 0 ? 'true' : 'false'
                console.log( 'Matching user is ' + ( result.rowCount === 0 ? 'NOT ' : '' )+ 'found.' )
                const soapResult = getAuthResultSOAP( authResult )
                console.log( 'Returning SOAP: ' + soapResult )
                response.send(200, soapResult )
              } )
              .catch( (e) => {
                console.log(e);
                response.send(500, getAuthResultSOAP('false') )
               })
        }) // end sql connect
      }); // end xmlparse
    }
  }
  catch (ex)
  {
    console.log( 'ERROR: ' + ex.message )
    return response.end( getAuthResultSOAP( 'false' ) )
  }
}

// MERGE AUTH RESULT TO RESPONSE SOAP
function getAuthResultSOAP( authResult ) {
  return '<?xml version="1.0" encoding="utf-8"?>' +
      '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
      '<soap:Body>' +
      '<AuthenticateResult xmlns="urn:authentication.soap.sforce.com">' +
        `<Authenticated>${authResult}</Authenticated>` +
      '</AuthenticateResult>' +
      '</soap:Body>' +
      '</soap:Envelope>'
}

server.post( "/", validateRequest, handleAuthQuery )

// SEND WSDL IF REQUESTED
server.get( "*", function (req, res, next) {
  if( req.url.toLowerCase().endsWith("wsdl") ) {
    res.setHeader('Content-Type', 'text/xml; charset=utf-8');
    require('fs').readFile(path.join(__dirname,'./delegated-auth.wsdl'), 'utf8', function(err, data) {
      if (err) throw err;
      res.send( 200, data.toString() );
    });
  } else {
    return next(new Error("Invalid Request"));
  }
} )

server.listen( process.env.PORT, function () {
  console.log( '%s listening at %s', server.name, server.url )
} )