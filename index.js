const express = require('express');
const snowflake = require('snowflake-sdk');
const app = express();
const port = 8080;
const cors = require('cors');
const bodyParser = require('body-parser');
const AWS = require('aws-sdk');
const s3 = new AWS.S3();
const crypto = require('crypto');
const { promisify } = require('util');


// Global variable to store loaded S3 data
let s3SnomedCodesData = [];

// Use CORS middleware
app.use(cors());

const allowedOrigins = [
    'http://localhost:4200',
    'http://medfusion-frontend.s3-website.us-east-2.amazonaws.com'
  ];

app.use((req, res, next) => {
    console.log('Origin:', req.headers.origin);  // Debug origin
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
      console.log('Preflight request');
      return res.sendStatus(204);
    }
  
    next();
});

// Middleware to parse JSON bodies
app.use(express.json());

app.use(bodyParser.json());

// Snowflake connection configuration
const connection = snowflake.createConnection({
    account: 'oaa72049.east-us-2.azure',
    username: 'DEV1',
    password: 'Password@1',
    warehouse: 'HEALTHCARE_WAREHOUSE',
    database: 'HEALTHCARE_DB',
    schema: 'STG'
});

// Update AWS config to the correct region
AWS.config.update({
    region: 'us-east-2',  // Replace with your region
  });
const cognito = new AWS.CognitoIdentityServiceProvider();

// Set AWS credentials (this is optional if you are using environment variables or an IAM role)
AWS.config.update({
    accessKeyId: "AKIAQKPILYINTE2HWWMB",
    secretAccessKey: "kK68RvKnW7EkoigwKEJP9MizbyRP65N4qJC1E9+r",
    region: 'us-east-2' // Replace with your region
});

const USER_POOL_ID = 'us-east-2_ZUmy7Bcey';  // Replace with your User Pool ID
const CLIENT_ID = '5gvo2kgmh9meh0dsau0l31ha12';   // Replace with your App Client ID
const CLIENT_SECRET = 'intmv4corbci54f1b3h96m4v80ocer1jehiksnglofr5emhv4gq';


const mockLoginResponse = {
    "token": {
      "IdToken": "eyJraWQiOiJ5dm5jc3c3bm8...ABC123",  // Mock JWT token (id token)
      "AccessToken": "eyJraWQiOiJtZG8xNj...DEF456",  // Mock JWT token (access token)
      "RefreshToken": "eyJjdHkiOiJ0ZXh...GHI789",  // Mock refresh token
      "TokenType": "Bearer",
      "ExpiresIn": 3600  // Time in seconds until the token expires (1 hour)
    },
    "user": {
      "email": "user@example.com",  // Email used to login
      "firstname": "George",
      "lastname": "Smith",
      "username": "user123",  // Cognito username (if configured separately)
      "roles": ["user"],  // Roles or groups assigned to the user
      "authTime": "2024-10-10T15:30:00Z"  // Time the user authenticated
    }
  }


// Connect to Snowflake
connection.connect((err, conn) => {
    if (err) {
        console.error('Unable to connect: ' + err);
    } else {
        console.log('Successfully connected to Snowflake.');
    }
});



app.post('/create-user', async (req, res) => {
    const { username, email, firstname, lastname, password,phonenumber } = req.body;
  
    const params = {
      UserPoolId: USER_POOL_ID,
      Username: username,
      TemporaryPassword: password, // You can use a temporary password here
      UserAttributes: [
        { Name: 'email', Value: email },
        { Name: 'email_verified', Value: 'true' },
        { Name: 'given_name', Value: firstname },
        { Name: 'family_name', Value: lastname },
        { Name: 'phone_number', Value: "+91"+phonenumber}
      ],
    };
  
    try {
      // Call AWS Cognito to create a new user
      const result = await cognito.adminCreateUser(params).promise();
      res.json({ message: 'User created successfully', result });
    } catch (error) {
      console.error('Error creating user:', error);
      res.status(400).json({ error: error.message });
    }
});


function generateSecretHash(username, clientId, clientSecret) {
    return crypto
      .createHmac('SHA256', clientSecret)
      .update(username + clientId)
      .digest('base64');
  }

/**Login service **/
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const secretHash = generateSecretHash(username, CLIENT_ID, CLIENT_SECRET);

    const authParams = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: CLIENT_ID,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: secretHash
        }
    };

    try {
        // Step 1: Authenticate the user
        const authResponse = await cognito.initiateAuth(authParams).promise();

        console.log(authResponse)
        // Extract the access token from the authentication response
        //const accessToken = authResponse.AuthenticationResult.AccessToken;

        // Step 2: Get user details using the access token
        /*const userParams = {
            AccessToken: accessToken
        };*/

        // Retrieve user attributes
        //const userDetails = await cognito.getUser(userParams).promise();

        // Extract user attributes (firstname, lastname, email, etc.)
        /*const userAttributes = userDetails.UserAttributes.reduce((acc, attribute) => {
            acc[attribute.Name] = attribute.Value;
            return acc;
        }, {});*/


        const userAttributes = JSON.parse(authResponse.ChallengeParameters.userAttributes);
        // Return the user details and the authentication result (tokens)
        res.json({
            message: 'Login successful',
            token: authResponse.AuthenticationResult,
            user: {
                username: authResponse.ChallengeParameters.USER_ID_FOR_SRP,
                firstname: userAttributes.given_name || '',
                lastname: userAttributes.family_name || '',
                email: userAttributes.email || ''
            }
        });

    } catch (error) {
        console.log('Error logging in:', error);
        res.status(400).json({ error: 'Invalid Credential' });
    }
});

// Define an API endpoint to query data
app.get('/orderDetails', (req, res) => {
    const orderNumber = req.query.orderNumber;

    if (!orderNumber) {
        return res.status(400).send('Order number is required');
    }

    console.log('orderNumber --> ',orderNumber);

    // Parameterized query to prevent SQL injection
    const sqlText = `SELECT * FROM HEALTHCARE_DB.INTG.ZHO_SNO_ORDER_ADMINPATIENT AS ORDER_DETAILS
                                       LEFT JOIN HEALTHCARE_DB.MASTER.S3_SNO_PATIENT AS PATIENT
                                                 ON (ORDER_DETAILS.INTG_ORDAP_SERV_ADARNUM = PATIENT.AP_PATIENT_ID_1 OR ORDER_DETAILS.INTG_ORDAP_SERV_PHONE = PATIENT.AP_PATIENT_ID_2)
                                       LEFT JOIN HEALTHCARE_DB.MASTER.S3_SNO_ADMIN_PATIENT_CONTACT AS CONTACT
                                                 ON PATIENT.AP_PATIENT_SKEY = CONTACT.REF_AP_PC_PATIENT_SKEY WHERE ORDER_DETAILS.INTG_ORDAP_ORDER_ID = ?`;

    connection.execute({
        sqlText: sqlText,
        binds: [orderNumber],
        complete: (err, stmt, rows) => {
            if (err) {
                console.error('Failed to execute statement:', err.message);
                return res.status(500).send('Error executing query');
            }
            res.json(rows);
        }
    });
});

app.get('/patient-contact-details', (req, res) => {
    const patientId = req.query.patientId;

    if (!patientId) {
        return res.status(400).send('Patient ID is required');
    }

    console.log('patientId --> ',patientId);

    // Parameterized query to prevent SQL injection
    const sqlText = `SELECT * FROM HEALTHCARE_DB.STG.S3_SNO_STG_ADMIN_PATIENT_CONTACT WHERE REF_AP_APC_PATIENT_SKEY= ?`;
    connection.execute({
        sqlText: sqlText,
        binds: [patientId],
        complete: (err, stmt, rows) => {
            if (err) {
                console.error('Failed to execute statement:', err.message);
                return res.status(500).send('Error executing query');
            }
            res.json(rows);
        }
    });
});




app.post('/publish-orderdetails', async (req, res) => {

    const {
        status,
        organizationId,
        patient,
        orderNumber,
        encounters = []
    } = req.body;


    const {
        ref_ap_client_key,
        ref_ap_dept_key,
        ap_patient_skey,
        ap_merge_patient_skey,
        ap_patient_id_1,
        ap_patient_id_2,
        ap_patinet_id_3,
        ap_active_flag,
        ap_full_name,
        ap_last_name,
        ap_first_name,
        ap_street_address_1,
        ap_street_address_2,
        ap_city,
        ap_county_district,
        ap_state,
        ap_postal_code,
        ap_country,
        ap_gender_code,
        ap_gender_codesystem,
        ap_std_gender,
        ap_race_code,
        ap_race_codesystem,
        ap_std_race,
        ap_ethnicgroup_code,
        ap_ethnicgroup_codesystem,
        ap_std_ethnicgroup,
        ap_language_code,
        ap_language_code_system,
        ap_std_language,
        ap_birthdate,
        ap_deceased_flag,
        ap_deceased_date,
        ap_maritalstatus_code,
        ap_maritalstatus_codesystem,
        ap_std_maritalstatus,
        ap_multiple_births_status_flag,
        ap_multiple_births_number,
        ap_patinet_photo,
        ref_organization,
        ap_primary_phone,
        ap_primary_email,
        ap_fax,
        ap_comment,
        ap_message_ref,
        ap_created_dt,
        ap_modified_dt,
        ap_created_by,
        ap_modified_by,
        patientContactDetails
    } = patient;

    // Extract patientContactDetails into separate variables
    const {
        ap_contanct_skey,
        ref_ap_apc_patient_skey,
        apc_active_flag,
        apc_std_relationship,
        apc_full_name,
        apc_last_name,
        apc_first_name,
        apc_street_address_1,
        apc_street_address_2,
        apc_city,
        apc_county_district,
        apc_state,
        apc_postal_code,
        apc_country,
        apc_std_gender,
        apc_std_language,
        apc_primary_phone,
        apc_primary_email,
        apc_fax,
        apc_comment
    } = patientContactDetails || {};  // Use default empty object if patientContactDetails is undefined


    console.log(encounters);



    // Logging extracted variables
    console.log("patient ---> ", patient);
    console.log("patientContactDetails ---> ", patientContactDetails);

    let outputJson = {
        "ClinicalDocument": {
            "realmCode": {
                "code": "IN"
            },
            "typeId": {
                "_root": "2.16.840.1.113883.1.3",
                "_extension": "POCD_HD000040"
            },
            "templateId": [
                {
                    "_root": "2.16.840.1.113883.10.20.22.1.1"
                },
                {
                    "_root": "2.16.840.1.113883.10.20.22.1.2"
                }
            ],
            "title": "SevaParivar.com Health Summary",
            "confidentialityCode": {
                "_code": "N",
                "_codeSystem": "2.16.840.1.113883.5.25"
            },
            "languageCode": {
                "_code": "en-US"
            },
            "versionNumber": {
                "_value": "1"
            },
            "ap_message_ref": "",
            "recordTarget": {
                "patientRole": {
                    "patient": {
                        "ap_patient_skey": ap_patient_skey,
                        "ap_merge_patient_skey": ap_merge_patient_skey,
                        "ap_patient_id_1": ap_patient_id_1,
                        "ap_patient_id_2": ap_patient_id_2,
                        "ap_patient_id_3": ap_patinet_id_3,
                        "ap_active_flag": ap_active_flag,
                        "addr": {
                            "ap_street_address_1": ap_street_address_1,
                            "ap_street_address_2": ap_street_address_2,
                            "ap_city": ap_city,
                            "ap_county_district": ap_county_district,
                            "ap_state": ap_state,
                            "ap_postal_code": ap_postal_code,
                            "ap_country": ap_country
                        },
                        "name": {
                            "ap_first_name": ap_first_name,
                            "ap_last_name": ap_last_name,
                            "ap_full_name": ap_full_name
                        },
                        "administrativeGenderCode": {
                            "ap_gender_code": ap_gender_code,
                            "ap_gender_codesystem": ap_gender_codesystem,
                            "ap_std_gender": ap_std_gender
                        },
                        "birthTime": {
                            "ap_birthdate": ap_birthdate
                        },
                        "maritalStatusCode": {
                            "ap_maritalstatus_code": ap_maritalstatus_code,
                            "ap_std_maritalstatus": ap_std_maritalstatus,
                            "ap_maritalstatus_codesystem": ap_maritalstatus_codesystem
                        },
                        "raceCode": {
                            "ap_race_code": ap_race_code,
                            "ap_std_race": ap_std_race,
                            "ap_race_codesystem": ap_race_codesystem
                        },
                        "ethnicGroupCode": {
                            "ap_ethnicgroup_code": ap_ethnicgroup_code,
                            "ap_std_ethnicgroup": ap_std_ethnicgroup,
                            "ap_ethnicgroup_codesystem": ap_ethnicgroup_codesystem
                        },
                        "telecom": {
                            "ap_primary_phone": ap_primary_phone,
                            "ap_primary_email": ap_primary_email
                        },
                        "languageCommunication": {
                            "languageCode": {
                                "ap_language_code": ap_language_code,
                                "ap_language_code_system": ap_language_code_system,
                                "ap_std_language": ap_std_language
                            },
                            "preferenceInd": {
                                "value": "true"
                            }
                        },
                        "ap_comment": ap_comment,
                        "ap_cust_string_1": "",
                        "ap_cust_bigint_1": "",
                        "ap_cust_date_1": "",
                        "ap_cust_int_1": "",
                        "contact": {
                            "apc_active_flag": "Y",
                            "relationship": {
                                "apc_relationship_code": "",
                                "apc_std_relationship": apc_std_relationship,
                                "apc_relationship_codesystem": ""
                            },
                            "addr": {
                                "apc_street_address_1": apc_street_address_1,
                                "apc_street_address_2": apc_street_address_1,
                                "apc_city": apc_city,
                                "apc_county_district": apc_county_district,
                                "apc_state": apc_state,
                                "apc_postal_code": apc_postal_code,
                                "apc_country": apc_country
                            },
                            "telecom": {
                                "apc_primary_phone": apc_primary_phone,
                                "apc_primary_email": apc_primary_email
                            },
                            "guardianPerson": {
                                "name": {
                                    "apc_first_name": apc_first_name,
                                    "apc_last_name": apc_last_name,
                                    "apc_full_name": apc_full_name
                                }
                            },
                            "administrativeGenderCode": {
                                "apc_gender_code": apc_std_gender,
                                "apc_gender_codesystem": "",
                                "apc_std_gender": apc_std_gender
                            },
                            "languageCommunication": {
                                "languageCode": {
                                    "apc_language_code": "",
                                    "apc_language_code_system": "",
                                    "apc_std_language": apc_std_language
                                },
                                "preferenceInd": {
                                    "value": "true"
                                }
                            },
                            "apc_comment": apc_comment
                        }
                    }
                },
                "providerOrganization": {
                    "id": {
                        "_root": "2.16.840.1.113883.19"
                    },
                    "name": "Good Health Clinic",
                    "telecom": {
                        "_use": "WP",
                        "_value": "tel:(781)555-1212"
                    },
                    "addr": {
                        "streetAddressLine": "21 North Ave",
                        "city": "Burlington",
                        "state": "MA",
                        "postalCode": "02368",
                        "country": "USA"
                    }
                }
            },
            "encounters": encounters
        }
    };

    const currentDate = new Date();
    const year = currentDate.getFullYear();
    const day = String(currentDate.getDate()).padStart(2, '0'); // Ensure two digits
    const month = String(currentDate.getMonth() + 1).padStart(2, '0'); // Ensure two digits (Month is 0-based)

    const formattedDate = `${year}-${day}-${month}`; // Format as YYYY-DD-MM
    const timestamp = currentDate.getTime(); // Get timestamp (milliseconds since epoch)


    // S3 upload parameters
    bucketname = '';
    if(status === 'publish') {
       bucketname = 'bucketsnowintegration';
    } else {
       bucketname = 'draftorders';
    }
    const params = {
        Bucket: bucketname, // Replace with your bucket name
        Key: `${organizationId}_${ap_created_by}_${orderNumber}_${formattedDate}_${timestamp}.json`, // Filename to save in S3
        Body: JSON.stringify(outputJson, null, 2), // Convert JSON object to string with pretty printing
        ContentType: 'application/json', // MIME type
        Metadata: { // Add custom metadata
            orderId: orderNumber,
            organizationid: organizationId, // Metadata key-value pair
            patientname: ap_full_name,
            createdby: ap_created_by
        }
    };

    console.log("params ---> ",params)

    // Uploading to S3
    try {
        const data = await s3.upload(params).promise();
        console.log("Successfully uploaded data to S3", data);
        res.status(200).json({
            message: "Order details published and uploaded to S3 successfully",
            data: req.body
        });
    } catch (err) {
        console.error("Error uploading data to S3", err);
        res.status(500).json({
            message: "Failed to upload data to S3",
            error: err.message
        });
    }

});




// API endpoint to insert patient data
// API endpoint to insert patient data
app.post('/new-patient', async (req, res) => {
    // Extract parameters from the request body
    const {
        orderNumber,
        ref_ap_client_key,
        ref_ap_dept_key,
        ap_patient_skey,
        ap_merge_patient_skey,
        ap_patient_id_1,
        ap_patient_id_2,
        ap_patient_id_3,
        ap_active_flag,
        ap_full_name,
        ap_last_name,
        ap_first_name,
        ap_street_address_1,
        ap_street_address_2,
        ap_city,
        ap_county_district,
        ap_state,
        ap_postal_code,
        ap_country,
        ap_gender_code,
        ap_gender_codesystem,
        ap_std_gender,
        ap_race_code,
        ap_race_codesystem,
        ap_std_race,
        ap_ethnicgroup_code,
        ap_ethnicgroup_codesystem,
        ap_std_ethnicgroup,
        ap_language_code,
        ap_language_code_system,
        ap_std_language,
        ap_birthdate,
        ap_deceased_flag,
        ap_deceased_date,
        ap_maritalstatus_code,
        ap_maritalstatus_codesystem,
        ap_std_maritalstatus,
        ap_multiple_births_status_flag,
        ap_multiple_births_number,
        ap_patient_photo,
        ref_organization,
        ap_primary_phone,
        ap_primary_email,
        ap_fax,
        ap_comment,
        ap_message_ref,
        ap_created_dt,
        ap_modified_dt,
        ap_created_by,
        ap_modified_by,
        // Optional fields
        ap_cust_string_1,
        ap_cust_string_2,
        ap_cust_string_3,
        ap_cust_string_4,
        ap_cust_string_5,
        ap_cust_bigint_1,
        ap_cust_bigint_2,
        ap_cust_bigint_3,
        ap_cust_bigint_4,
        ap_cust_bigint_5,
        ap_cust_date_1,
        ap_cust_date_2,
        ap_cust_date_3,
        ap_cust_date_4,
        ap_cust_date_5,
        ap_cust_int_1,
        ap_cust_int_2,
        ap_cust_int_3,
        ap_cust_int_4,
        ap_cust_int_5,
        ap_contanct_skey,
        ref_ap_apc_patient_skey,
        apc_active_flag,
        apc_std_relationship,
        apc_full_name,
        apc_last_name,
        apc_first_name,
        apc_street_address_1,
        apc_street_address_2,
        apc_city,
        apc_county_district,
        apc_state,
        apc_postal_code,
        apc_country,
        apc_std_gender,
        apc_std_language,
        apc_primary_phone,
        apc_primary_email,
        apc_fax
    } = req.body;

    console.log("req.body ---> ", req.body);

    // Construct SQL query
    const sql = `
    INSERT INTO HEALTHCARE_DB.STG.S3_SNO_STG_PATIENT (
      REF_AP_CLIENT_KEY,
      REF_AP_DEPT_KEY,
      AP_PATIENT_SKEY, 
      AP_MERGE_PATIENT_SKEY,
      AP_PATIENT_ID_1,
      AP_PATIENT_ID_2,                                                
      AP_PATINET_ID_3,
      AP_ACTIVE_FLAG,
      AP_FULL_NAME,
      AP_LAST_NAME,
      AP_FIRST_NAME,
      AP_STREET_ADDRESS_1,
      AP_STREET_ADDRESS_2,
      AP_CITY,
      AP_COUNTY_DISTRICT,
      AP_STATE,
      AP_POSTAL_CODE,
      AP_COUNTRY,
      AP_CNCT_KEY,
      AP_GENDER_CODE,
      AP_GENDER_CODESYSTEM,
      AP_STD_GENDER,
      AP_RACE_CODE,
      AP_RACE_CODESYSTEM,
      AP_STD_RACE,
      AP_ETHNICGROUP_CODE,
      AP_ETHNICGROUP_CODESYSTEM,
      AP_STD_ETHNICGROUP,
      AP_LANGUAGE_CODE,
      AP_LANGUAGE_CODE_SYSTEM,
      AP_STD_LANGUAGE,
      AP_BIRTHDATE,
      AP_DECEASED_FLAG,
      AP_DECEASED_DATE,
      AP_MARITALSTATUS_CODE,
      AP_MARITALSTATUS_CODESYSTEM,
      AP_STD_MARITALSTATUS,
      AP_MULTIPLE_BIRTHS_STATUS_FLAG,
      AP_MULTIPLE_BIRTHS_NUMBER,
      AP_PATINET_PHOTO,
      REF_AP_GP_KEY,
      REF_ORGANIZATION,
      AP_PRIMARY_PHONE,
      AP_PRIMARY_EMAIL,
      AP_FAX,
      AP_COMMENT,
      AP_CUST_STRING_1,
      AP_CUST_STRING_2,
      AP_CUST_STRING_3,
      AP_CUST_STRING_4,
      AP_CUST_STRING_5,
      AP_CUST_BIGINT_1,
      AP_CUST_BIGINT_2,
      AP_CUST_BIGINT_3,
      AP_CUST_BIGINT_4,
      AP_CUST_BIGINT_5,
      AP_CUST_DATE_1,
      AP_CUST_DATE_2,
      AP_CUST_DATE_3,
      AP_CUST_DATE_4,
      AP_CUST_DATE_5,
      AP_CUST_INT_1,
      AP_CUST_INT_2,
      AP_CUST_INT_3,
      AP_CUST_INT_4,
      AP_CUST_INT_5,
      AP_MESSAGE_REF,
      AP_CREATED_DT,
      AP_MODIFIED_DT,
      AP_CREATED_BY,
      AP_MODIFIED_BY
    ) VALUES (
      ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?,?
    )
  `;


    //Patient Contact Insert Query
    // Define the SQL INSERT statement
    const patientContactSQL = `
        INSERT INTO HEALTHCARE_DB.STG.S3_SNO_STG_ADMIN_PATIENT_CONTACT (
            APC_CONTACT_SKEY,
            REF_AP_APC_PATIENT_SKEY,
            APC_ACTIVE_FLAG,
            APC_STD_RELATIONSHIP,
            APC_FULL_NAME,
            APC_LAST_NAME,
            APC_FIRST_NAME,
            APC_STREET_ADDRESS_1,
            APC_STREET_ADDRESS_2,
            APC_CITY,
            APC_COUNTY_DISTRICT,
            APC_STATE,
            APC_POSTAL_CODE,
            APC_COUNTRY,
            APC_STD_GENDER,
            APC_STD_LANGUAGE,
            APC_PRIMARY_PHONE,
            APC_PRIMARY_EMAIL,
            APC_FAX
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    `;

    // Construct the array of values, replacing undefined with null
    const values = [
        //ref_ap_client_key,
        "1",
        // ref_ap_dept_key,
        "2",
        ap_patient_skey,
        //"3",
        // ap_merge_patient_skey,
        "4",
        ap_patient_id_1,
        ap_patient_id_2,
        ap_patient_id_3 || null,
        ap_active_flag,
        ap_full_name,
        ap_last_name,
        ap_first_name,
        ap_street_address_1,
        ap_street_address_2,
        ap_city,
        ap_county_district,
        ap_state,
        ap_postal_code,
        ap_country,
        null,  // AP_CNCT_KEY if not provided
        ap_gender_code,
        ap_gender_codesystem,
        ap_std_gender,
        ap_race_code,
        ap_race_codesystem,
        ap_std_race,
        ap_ethnicgroup_code,
        ap_ethnicgroup_codesystem,
        ap_std_ethnicgroup,
        ap_language_code || null,
        ap_language_code_system || null,
        ap_std_language || null,
        ap_birthdate ? new Date(ap_birthdate) : null,
        ap_deceased_flag,
        ap_deceased_date ? new Date(ap_deceased_date) : null,
        ap_maritalstatus_code,
        ap_maritalstatus_codesystem,
        ap_std_maritalstatus,
        ap_multiple_births_status_flag,
        ap_multiple_births_number,
        ap_patient_photo || null,
        null,  // REF_AP_GP_KEY if not provided
        ref_organization,
        ap_primary_phone,
        ap_primary_email,
        ap_fax,
        ap_comment,
        ap_cust_string_1 || null,
        ap_cust_string_2 || null,
        ap_cust_string_3 || null,
        ap_cust_string_4 || null,
        ap_cust_string_5 || null,
        ap_cust_bigint_1 || null,
        ap_cust_bigint_2 || null,
        ap_cust_bigint_3 || null,
        ap_cust_bigint_4 || null,
        ap_cust_bigint_5 || null,
        ap_cust_date_1 ? new Date(ap_cust_date_1) : null,
        ap_cust_date_2 ? new Date(ap_cust_date_2) : null,
        ap_cust_date_3 ? new Date(ap_cust_date_3) : null,
        ap_cust_date_4 ? new Date(ap_cust_date_4) : null,
        ap_cust_date_5 ? new Date(ap_cust_date_5) : null,
        ap_cust_int_1 || null,
        ap_cust_int_2 || null,
        ap_cust_int_3 || null,
        ap_cust_int_4 || null,
        ap_cust_int_5 || null,
        ap_message_ref,
        ap_created_dt ? new Date(ap_created_dt) : null,
        ap_modified_dt ? new Date(ap_modified_dt) : null,
        ap_created_by,
        ap_modified_by
    ];

    const patientContactValues = [
        ap_contanct_skey,
        ap_patient_skey,
        true,
        apc_std_relationship,
        apc_full_name,
        apc_last_name,
        apc_first_name,
        apc_street_address_1,
        apc_street_address_2,
        apc_city,
        apc_county_district,
        apc_state,
        apc_postal_code,
        apc_country,
        apc_std_gender,
        apc_std_language,
        apc_primary_phone,
        apc_primary_email,
        apc_fax
    ]

    // Log the values array to debug
    console.log("values array ---> ", values);
    console.log("Patient Contact Values Array: ", patientContactValues);


    // Execute the query
// Execute the patient insert query
    await new Promise((resolve, reject) => {
        connection.execute({
            sqlText: sql,
            binds: values,
            complete: (err, stmt) => {
                if (err) {
                    console.error('Failed to execute patient insert query:', err);
                    return reject(err);
                }
                console.log('Patient record inserted successfully:', stmt.getSqlText());
                resolve();
            }
        });
    });

    // Update the order table
    await new Promise((resolve, reject) => {
        const updateOrderSql = `
                UPDATE HEALTHCARE_DB.STG.INTG_ZHO_SNO_STG_ORDER_ADMINPATIENT
                SET REF_AP_PATIENT_SKEY = ?
                WHERE INTG_ORDAP_ORDER_ID = ?
            `;
        connection.execute({
            sqlText: updateOrderSql,
            binds: [ap_patient_skey, orderNumber],
            complete: (err, stmt) => {
                if (err) {
                    console.error('Failed to update patient ID in order table:', err);
                    return reject(err);
                }
                console.log('Patient ID updated in order table:', stmt.getSqlText());
                resolve();
            }
        });
    });

    // Insert patient contact details
    await new Promise((resolve, reject) => {
        connection.execute({
            sqlText: patientContactSQL,
            binds: patientContactValues,
            complete: (err, stmt) => {
                if (err) {
                    console.error('Failed to insert patient contact details:', err.message);
                    return reject(err);
                }
                console.log('Patient contact details inserted successfully:', stmt.getSqlText());
                resolve();
            }
        });
    });

    res.json({ status: 'Success', message: 'Patient record inserted and updated successfully' });

});

app.post('/create-practitioner', (req, res) => {
    const practitioner = req.body;

    // Validate the incoming practitioner data
    if (!practitioner.apra_first_name || !practitioner.apra_last_name || !practitioner.apra_primary_email) {
        return res.status(400).json({ error: 'First name, last name, and primary email are required' });
    }

    // Respond with success message and created practitioner data
    res.status(201).json({ message: 'Practitioner created successfully', practitioner });
});

app.post('/create-facility', (req, res) => {
    const facility = req.body;

    if (!facility.fac_name || !facility.fac_city || !facility.fac_state) {
        return res.status(400).json({ message: 'Required fields missing' });
    }
    
    // Respond with success message and created practitioner data
    res.status(201).json({ message: 'Facility created successfully', facility });
});

app.get('/draft-orders', async (req, res) => {
    const { organizationId } = req.query;  // Assume organizationId is passed as a query parameter

    try {
        // Step 1: List objects in the bucket using organizationId as the prefix
        const bucketName = 'draftorders'; // Replace with your bucket name
        const listParams = {
            Bucket: bucketName,
            Prefix: `${organizationId}_`  // Prefix to filter files starting with organizationId
        };

        const listedObjects = await s3.listObjectsV2(listParams).promise();
        
        if (!listedObjects.Contents.length) {
            return res.status(404).send('No files found for the given organization.');
        }

        // Step 2: Loop through the objects and get metadata for each file
        const fileDetailsPromises = listedObjects.Contents.map(async (object) => {
            const headParams = {
                Bucket: bucketName,
                Key: object.Key
            };
            const headData = await s3.headObject(headParams).promise();  // Fetch metadata for each object
            console.log("headData  -> ",headData.Metadata)
            console.log("headData111  -> ",JSON.stringify(headData.Metadata))

            const parsedHeadData = JSON.parse(JSON.stringify(headData.Metadata));

            // Extract metadata (e.g., orderId and created_by)
            // const orderId = parsedHeadData.orderid;       // Correct access for 'orderid'
            // const createdBy = parsedHeadData.createdby;  // Correct access for 'created-by'
            // const organizationId = parsedHeadData.organizationid; // Correct access for 'organization-id'

            return {
                fileName: object.Key,
                orderId: parsedHeadData.orderid || 'N/A',     
                serviceTo: parsedHeadData.patientname || 'N/A',       
                createdBy: parsedHeadData.createdby || 'N/A',       
            };
        });

        // Step 3: Resolve all metadata retrieval promises
        const draftorders = await Promise.all(fileDetailsPromises);

        // Step 4: Return the file details with metadata
        res.json({ draftorders });

    } catch (error) {
        console.error('Error listing objects:', error);
        res.status(500).send('Error fetching files from S3.');
    }
});

const getObjectAsync = promisify(s3.getObject).bind(s3);
// API endpoint to get items
app.get('/snomed-codes', async (req, res) => {
    const query = req.query.searchQuery?.toLowerCase() || '';

    console.log("qrryy  ",query);

    if (!query) {
        return res.json([]);
    }

    // Load data from S3
    // const items = await loadDataFromS3();
  
    // Filter items based on the search query
    const filteredItems = s3SnomedCodesData.filter(item => item.snomeddesc.toLowerCase().includes(query));
  
    res.json(filteredItems);
});

// Function to load data from S3 at server startup
async function loadDataFromS3() {
    try {
        const data = await getObjectAsync({
            Bucket: 'medfusion-referencedata',
            Key: 'snomedcodes_json.json',
        });
        // Parse and store the JSON data in the global variable
        s3SnomedCodesData = JSON.parse(data.Body.toString());
        console.log('S3 data loaded successfully.');
    } catch (error) {
        console.error('Error loading data from S3:', error);
        throw error;
    }
}

// Start the server after loading S3 data
/*async function startServer() {
    try {
        // Load S3 data before starting the server
        await loadDataFromS3();
    } catch (error) {
        console.error('Failed to start the server:', error);
    }
}*/

//startServer();

// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
