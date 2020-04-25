# s3-operator
A Kubernetes operator to create s3 folders.

This custom operator will create a folder in the s3 bucket. User will have access to the folder created in the S3 bucket.

1)S3 bucket name
2)Operator name and namespace where the operator pod will run
3)Secret which contains IAM user name who will access to S3 folder

## Team Information

| Name | NEU ID | Email Address |
| --- | --- | --- |
| Akash Katakam | 001400025 | katakam.a@husky.neu.edu |
| Ravi Kiran    | 001439467 | lnu.ra@husky.neu.edu |
| Veena Iyer    | 001447061  | iyer.v@husky.neu.edu|


To create instances of this custom operator:

1)Install this operator using helm chart from the following link:
```
https://github.com/VeenaIyer-17/s3-operator.git
```
2)Create instance of the custom operator. Sample CR
```
apiVersion: csye7374/v1alpha1
kind: folder
metadata:
  name: username
  namespace: somenamespace
spec:
  username: yourusername
  userSecret:
    name: username-secret

```
