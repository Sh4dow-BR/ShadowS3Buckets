<div align="center">

# ShadowS3Buckets

![GitHub repo size](https://img.shields.io/github/repo-size/Sh4dow-BR/ShadowS3Buckets)
![GitHub language count](https://img.shields.io/github/languages/count/Sh4dow-BR/ShadowS3Buckets)
![GitHub forks](https://img.shields.io/github/forks/Sh4dow-BR/ShadowS3Buckets)
![Bitbucket open issues](https://img.shields.io/bitbucket/issues/Sh4dow-BR/ShadowS3Buckets)
![Bitbucket open pull requests](https://img.shields.io/bitbucket/pr-raw/Sh4dow-BR/ShadowS3Buckets)

<img src="docs/imgs/logo.png" alt="ShadowS3Buckets Logo" width=500>

## It's a Python script that validates AWS S3 buckets in an account or various accounts checking for wrongly configured buckets.
</div>

### ⭐ What can ShadowS3Buckets do and how can it help you?

- It can make API calls with the default configured AWS profile and different profiles with the '-p' parameter.
- It can make API calls to different AWS accounts to do the same checks inside the account.
- It's built in a modular way, with various functions, so you can choose which checks you'd like to see.
- It can assume roles in as many other accounts as you need to check the buckets in the account.
- It can list all the bucket names of each account.
- It can check the server-side encryption status of each bucket.
- It can check the versioning status of each bucket.
- It can check the public access block status of each bucket.
- It can check the bucket policy status of each bucket.
- It can output the JSON bucket policy of each bucket.
- It has various comments inside of it to help understand the overall flow and logic of each function.
- Every function has a try/except statement to help avoid unexpected errors.


### ⭐ What are AWS S3 buckets?

Amazon Simple Storage Service (Amazon S3) is an object storage service that offers industry-leading scalability, data availability, security, and performance. Customers of all sizes and industries can use Amazon S3 to store and protect any amount of data for a range of use cases, such as data lakes, websites, mobile applications, backup and restore, archive, enterprise applications, IoT devices, and big data analytics. Amazon S3 provides management features so that you can optimize, organize, and configure access to your data to meet your specific business, organizational, and compliance requirements. <b>Source: [AWS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html)</b>

If you want to check out the official S3 Security best practices guide with recommendations of AWS, check it out [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)!

## 💻 Prerequesites


You need to have [git](https://git-scm.com/downloads) installed to clone the repo.

You need to have at least [Python 3.9](https://www.python.org/downloads/) installed to use pip.

<b>OPTIONAL:</b> This script uses the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) and it can be installed beforehand or when you execute the pip command.

<b>OPTIONAL:</b> This script also uses the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and it can be installed beforehand or when you execute the pip command.


## 🚀 Downloading ShadowS3Buckets & it's requirements

To download ShadowS3Buckets, follow these steps

Linux, macOS & Windows:
```
git clone https://github.com/Sh4dow-BR/ShadowS3Buckets.git
cd ShadowS3Buckets
pip install -r requirements.txt
```


## ☁ AWS profiles

ShadowS3Buckets uses AWS Credentials under the hood to make API calls to Amazon.

You can follow any authentication method as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence).

So before running the script, make sure you have properly configured your AWS CLI with valid credentials.

<b>OBSERVATION:</b> I have only tested this with the traditional IAM User Access Keys but I imagine this works with the other methods!

```console
aws configure
```


## ☁ AWS IAM permissions

This example IAM policy is based on the principle of providing [least privilege](https://csrc.nist.gov/glossary/term/least_privilege) to the IAM user/credentials making the API calls.

Implementing least-privilege access is fundamental in reducing security risk and the impact that could result from errors or malicious intent. <b>Source: [AWS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html#least)</b>


While it's the best-case scenario to create a separate user specific to this script, if you're using the "AdministratorAccess" policy with "*" permission to all actions and resources, this example policy won't be necessary as it intends to limit the actions that can be called with the user.

<hr>

Example JSON permissions policy that permits only the required actions: 

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ShadowS3Buckets",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketACL",
                "s3:GetBucketPolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

<hr>

If you've configured [resource groups](https://docs.aws.amazon.com/ARG/latest/userguide/resource-groups.html) for your S3 buckets, you can have your "Resource" in the following way:

```"Resource": "arn:aws:resource-groups:*:123456789012:group/*"``` instead of ```"Resource": "*"```.

Example JSON policy with Resource Groups:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ShadowS3Buckets",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketACL",
                "s3:GetBucketPolicy"
            ],
            "Resource": "arn:aws:resource-groups:*:123456789012:group/*"
        }
    ]
}
```

<hr>

To further improve the security of the following IAM permissions policy, it's possible to add [conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html) but it's optional.

Example JSON policy with a condition that only permits these actions if the username = johndoe:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ShadowS3Buckets",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketACL",
                "s3:GetBucketPolicy"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:username": [
                        "johndoe"
                    ]
                }
            }
        }
    ]
}
```

## ☁ AWS Assume Role in different accounts

There is a function inside the script, 'assume_role', that will try to assume a role in other AWS accounts (a 12-digit #) that you define in the 'ACCOUNT_IDS' constant. 

It has its own set of modules/blocks of code made up of functions that will run and you can enable or disable which ones will execute. It's the same API calls of the single account check but it will apply to every account you define.

This function usually works well from the management/delegated account in a AWS Organization but you can also assume roles in a cross-account situation.

If you want to assume a role in a cross-account that isn't in the AWS Organization, you will need to create a role in "Account B" with a trust relationship to permit "Account A" to assume a role in that account.

By default, the 'assume_role' function in this script will call upon the 'OrganizationAccountAccessRole' role in "Account B" as it's the default in an AWS Organization but it can be changed to the role names you have configured.

<hr>

### Configuring or editing a role in "Account B"

When you create or edit a role in "Account B" it's necessary to configure and attach <b>2 policies</b> to the role:

A trust relationship policy & a permissions policy.

<hr>

#### Trust relationship policy:

Example JSON trust relationship policy that permits only 1 IAM User in "Account A" to assume a role in "Account B" <b>(Best case scenario)</b>:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<ACCOUNT_A_ACCOUNT_NUMER>:<IAM_USER_IN_ACCOUNT_A"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

Example JSON trust policy that permits every IAM User in "Account A" to assume a role in "Account B" <b>(This is the AWS Organization default and it's very dangerous)</b>:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<ACCOUNT_A_ACCOUNT_NUMER>:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

<hr>

#### Permissions policy:

This permissions policy is the same configured for a single IAM User.

You can use the same JSON policy that you used when configuring the [IAM](#-aws-iam-permissions-1) permissions.


## 🗡 Using ShadowS3Buckets

To use ShadowS3Buckets, follow these steps:

<b>Option #1:</b> (I'd recommend this way as it's easier)
1. Open the ShadowS3Buckets.py file in your favorite IDE and make the necessary changes to the modules you want to run and optionally add the other Account IDs.
2. Run the Python file from your IDE and it will make the API calls with the 'default' AWS profile.
3. Optionally, you can add the '-p' parameter to make API calls with a specific profile.
```python
ShadowS3Buckets.py -p <insert_profile_here>
```
4. If you want to, run the help menu, add the '-h' parameter.
```python
ShadowS3Buckets.py -h
```

<b>Option #2:</b>
1. Open the ShadowS3Buckets.py file in your favorite IDE and make the necessary changes to the modules you want to run and optionally add the other Account IDs.
2. Open your CMD or Terminal and change directories into the location where you cloned the files to.
3. Insert the following code if you want to run it with the 'default' AWS profile:
```python
python3 ShadowS3Buckets.py
```
4. Optionally, you can add the '-p' parameter to make API calls with a specific profile.
```python
python3 ShadowS3Buckets.py -p <insert_profile_here>
```
5. If you want to, run the help menu, add the '-h' parameter.
```python
Python3 ShadowS3Buckets.py -h
```


## 📫 Contributing to ShadowS3Buckets

Would you like to help out with the project?

To contribute to ShadowS3Buckets, follow these steps:

1. Fork this repo
2. Create a branch: `git checkout -b <name_of_the_branch>`
3. Make your changes in your favorite IDE and stage the changes: `git add .`
4. Make a commit with a message of the changes you made: `git commit -m '<commit_message>'`
5. Send it to the original branch: `git push`
6. Create a pull request using the [pull request template](docs\pull_request_template.md)

As an alternative, check out the official GitHub documentation on how to [contribute to projects](https://docs.github.com/en/get-started/quickstart/contributing-to-projects).

## 🐞 Bugs or feature requests?

In the .github folder, there are 2 files: [BUG_REPORT.yaml](.github\ISSUE_TEMPLATE\BUG_REPORT.yaml) & [FEATURE_REQUEST.yaml](.github\ISSUE_TEMPLATE\FEATURE_REQUEST.yaml) that comes preloaded with information that will help theses requests.

## 😕 Known issues and possible future features

Since the project is still in the early stages, a lot of improvements can be made, and here are some possible features?

- It only scans in the default region that the AWS profile is configured to, so it would be nice to have other regions as well
- There are additional checks that can be made on each S3 bucket but this project has already taken a lot of time and additional help would be needed


## 😏 Code of conduct

Check out the code of conduct [here](docs/CODE_OF_CONDUCT.md).

## 📝 License

This project is under the MIT License. Check out the license [here](LICENSE) for more details.

[⬆ Return to the top](#shadows3buckets)