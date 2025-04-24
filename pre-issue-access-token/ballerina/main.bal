import ballerina/http;
import ballerina/log;
import ballerina/lang.runtime;

service / on new http:Listener(9090) {

    resource function post filter(http:Caller caller, http:Request req) returns error? {
        json bodyJson = check req.getJsonPayload();
        map<json> body = <map<json>>bodyJson;
        
        string actionType = body["actionType"].toString();
        map<json> event = <map<json>>body["event"];
        map<json> request = <map<json>>event["request"];
        string grantType = request["grantType"].toString();

        map<json> accessToken = <map<json>> event["accessToken"];
        json[] existingScopes = <json[]> accessToken["scopes"];

        string CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
        string ALLOWED_SCOPE = "read:metrics";

        if actionType != "PRE_ISSUE_ACCESS_TOKEN" || grantType == "" {
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
                    operations.push({
                        op: "remove",
                        path: "/accessToken/scopes/" + index.toString()
                    });
                }
                index += 1;
            }

            json responseBody = {
                actionStatus: "SUCCESS",
                operations: operations
            };
            http:Response res = new;
            res.statusCode = 200;
            res.setJsonPayload(responseBody);
            check caller->respond(res);
            return;
        }

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
