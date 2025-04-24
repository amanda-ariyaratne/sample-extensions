import ballerina/http;
import ballerina/log;

service / on new http:Listener(9090) {

    resource function post filter(http:Caller caller, http:Request req) returns error? {
        json bodyJson = check req.getJsonPayload();
        log:printInfo("Received request payload: " + bodyJson.toJsonString());

        map<json> body = <map<json>>bodyJson;

        string actionType = body["actionType"].toString();
        log:printInfo("Action type: " + actionType);

        map<json> event = <map<json>> body["event"];
        map<json> request = <map<json>> event["request"];
        string grantType = request["grantType"].toString();
        log:printInfo("Grant type: " + grantType);

        map<json> accessToken = <map<json>> event["accessToken"];
        json[] existingScopes = <json[]> accessToken["scopes"];
        log:printInfo("Existing scopes: " + existingScopes.toString());

        string CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
        string ALLOWED_SCOPE = "read:metrics";

        if actionType != "PRE_ISSUE_ACCESS_TOKEN" || grantType == "" {
            log:printError("Invalid or missing actionType or grantType");

            json responseBody = {
                actionStatus: "FAILED",
                failureReason: "invalid_request",
                failureDescription: "Invalid or missing clientId or actionType"
            };
            http:Response res = new;
            res.statusCode = 200;
            res.setJsonPayload(responseBody);
            check caller->respond(res);
            return;
        }

        if grantType == CLIENT_CREDENTIALS_GRANT_TYPE {
            json[] operations = [];
            int index = 0;

            foreach var scope in existingScopes {
                if scope.toString() != ALLOWED_SCOPE {
                    string path = "/accessToken/scopes/" + index.toString();
                    operations.push({
                        op: "remove",
                        path: path
                    });
                    log:printInfo("Removing unauthorized scope at: " + path);
                }
                index += 1;
            }

            json responseBody = {
                actionStatus: "SUCCESS",
                operations: operations
            };
            log:printInfo("Returning modified token response: " + responseBody.toJsonString());

            http:Response res = new;
            res.statusCode = 200;
            res.setJsonPayload(responseBody);
            check caller->respond(res);
            return;
        }

        log:printInfo("Grant type is not client_credentials, allowing default token issuance");

        // Default behavior
        json responseBody = {
            actionStatus: "SUCCESS"
        };
        http:Response res = new;
        res.statusCode = 200;
        res.setJsonPayload(responseBody);
        check caller->respond(res);
    }
}
