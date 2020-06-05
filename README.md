# Zero_Trust_Project

OPA 
curl -X POST http://localhost:8181/v1/data/myapi/policy/allow --data-binary '{ "input": { "user": "Sam", "access": "read", "object":"server123", "score":"90" } }'
curl -X POST -H "Content-Type: application/json" -d '{"input": {"user": "Sam", "access": "read", "object":"server123", "score":"90"}}' localhost:8181/v1/data/authz/allow
