# ProtoVault Breach   

The challenge provides a zip file.Download & Extract it with the PSW: `BloodBreathSoulFire` it gives us the project folders.  
You’ve been tasked with tracing the origin of the breach and uncovering the vulnerability before the anonymous adversary can exploit it further – all while protecting the Order’s secrets without giving in to their demands.

Two clues are in your possession:

    The ransom scroll (email)
    The source glyphs of the Corespell (application code)

Find the leak. Seal the breach. Keep the Order's secrets from falling into the wrong hands.

---   

The problem states that the first clue is an email.  
Let's examine it.  

## KEY1

**Q1: Determine if the leak could have come from the application. Review the database connection string to ensure it is secure. Submit the connection string here.  

  
The image in the email shows an excerpt of SQL data:  

```COPY public.item_types (id, name, description) FROM stdin;  

1	Biological Samples	Preserved specimens of rare or hazardous organisms  

2	Prototype Devices	Experimental technologies under development  

3	Confidential Documents	Sensitive research reports  

4	Hazardous Chemicals	Toxic, corrosive, or otherwise dangerous substances  
```

The goal is to prove that the attacker had access to real data to make the threat more convincing.  

The ransom image shows a PostgreSQL dump (COPY public.item_types (id, name, description) FROM stdin;) => The repository must contain a PostgreSQL configuration/connection string and there might be a backup script (which can easily cause leaks).  

We don't know which commit exposed the secret. `git grep -nI "SQLALCHEMY_DATABASE_URI" $(git rev-list --all) `allows us to search all commits.  

<img width="953" height="907" alt="1" src="https://github.com/user-attachments/assets/2c89265f-30cf-49bb-9189-75cb95c9393d" />  

We can see that recently, the production host and a dedicated user were used with `sslmode=verify-full` (requires SSL and CN verification). However, previously, a much less secure string was used: no SSL, the full password was exposed, and the host was 127.0.0.1. This shows that the repo once contained sensitive information -> increases the likelihood that the leak originated from the team's application/process.  


Therefore, after synthesizing the information, the answer for the first question will be:    
A1:  


`Yes, postgresql://assetdba:8d631d2207ec1debaafd806822122250@pgsql_prod_db01.protoguard.local/pgamgt?sslmode=verify-full`  

----
## KEY2  

Q2:  Review the other source files. Which one may have leaked the database? Provide the file name.  

Identify a file in the source code that has the potential to leak the database (could be from a backup → uploaded to a public location).

The ransom image:  
Shows a PostgreSQL dump: COPY … FROM stdin; → confirms the leaked data is a PostgreSQL dump. The taunt: "Your encoding trick isn’t going to fool anyone." → This is not real encryption, but a form of "fake" encryption/obfuscation. In a Python project, the classic culprit is ROT13.

In the lab problem (Q3 & Q4), there is one notable point:  
It asks for the "public address of the leak" and requires downloading it to verify (extracting Naomi's hash). → The dump must be located at a public URL. The most common scenario: a misconfigured public S3 object (or similar blob storage endpoint).  
Typically, a Python/Flask project often has a util/ directory containing utilities like backup scripts.

PostgreSQL backup usually uses `pg_dump`.

Based on the above information, we will search for backup traces in the entire history, in case the file was deleted.  
`git grep -nI 'pg_dump\|ROT13\|rot_13\|db_backup' $(git rev-list --all)`  

<img width="1053" height="909" alt="2" src="https://github.com/user-attachments/assets/cd61b309-9e0b-4f93-b20f-4a939efaa797" />  
From the grep results, we can reconstruct the behavior of this script:  

1. Create a database dump:
      `dump_cmd = f"pg_dump -U {DB_USER} {DB_NAME} > /tmp/{BACKUP_FILENAME}"`
       → pg_dump exports the entire database to a .sql file.

3. ROT13 "Encoding":
    `encoded = codecs.encode(data, "rot_13")`
   
    → The data is "encrypted" using ROT13 (just letter shifting, very easy to reverse).

4. Name the file .xyz:
    `BACKUP_FILENAME = "db_backup.xyz"`
   
    → Changes the file extension to disguise it, but it's essentially a text dump.

5. Upload to S3:
    `S3_KEY = "db_backup.xyz"`
   
    → The backup file is uploaded to an Amazon S3 bucket.

Thus, this file is very sensitive; if made public, it can easily be exploited. I searched in the current source code but couldn't find it, so perhaps the dev team also realized this and removed it. Therefore, the answer will be:

A2:  
`app/util/backup_db.py`  

 ----  
 ## KEY3  
Q3:  Using the results of your analysis, discover the public address of the database leak. Verify the contents of the leak by submitting the password hash for Naomi Adler.  


As mentioned above, the developer used S3 for upload. The general pattern for a public S3 access URL looks like this:

`https://<bucket>.s3.<region>.amazonaws.com/<object>`

Now let's try to find the bucket and region in the code.

`git grep -nI 'S3_BUCKET\|S3_REGION|S3_bucket\|S3_region' $(git rev-list --all)`  
<img width="1029" height="968" alt="3" src="https://github.com/user-attachments/assets/feefc853-e942-4b03-a90a-cd6bb68e442a" />  

Here we get:
`S3_BUCKET = "protoguard-asset-management"`  


But we don't find REGION. After searching for a while, I tried tracing the most recent commit of backup_db.py to see more.  


`git log -p -- app/util/backup_db.py | grep S3_REGION -A 2 -B 2`  

<img width="871" height="867" alt="4" src="https://github.com/user-attachments/assets/7042abd1-e653-460f-8a24-8f882362e1fd" />

 And we found everything we needed. It seems I've been a bit long-winded already.  
 ```
S3_BUCKET = "protoguard-asset-management"
S3_KEY = "db_backup.xyz"
S3_REGION = "us-east-2"
```
With this information, we can assemble the URL:  
`https://protoguard-asset-management.s3.us-east-2.amazonaws.com/db_backup.xyz`  
And successfully, this file exists.  

<img width="679" height="134" alt="5" src="https://github.com/user-attachments/assets/b3f24c37-d32a-474b-a91e-e8e118697e7b" />    


The next task is to find the password hash for Naomi Adler.

I wrote a script to automate this process:  
```
<#
.SYNOPSIS
    Download a dump file from S3, decode ROT13, and extract Naomi Adler's password hash.
#>

param (
    [string]$Url = "https://protoguard-asset-management.s3.us-east-2.amazonaws.com/db_backup.xyz",
    [string]$Rot13File = "dump.rot13",
    [string]$DecodedFile = "dump.sql",
    [string]$TargetFirst = "Naomi",
    [string]$TargetLast = "Adler"
)

function Decode-Rot13($text) {
    return ($text.ToCharArray() | ForEach-Object {
        if ($_ -match '[A-Za-z]') {
            $base = if ($_ -cmatch '[A-Z]') { [int][char]'A' } else { [int][char]'a' }
            [char]((( [int][char]$_ - $base + 13) % 26) + $base)
        } else { $_ }
    }) -join ''
}

Write-Host "[1/4] Downloading leaked S3 object..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $Rot13File -ErrorAction Stop
Write-Host "[+] Downloaded file: $Rot13File"

Write-Host "[2/4] Decoding ROT13..." -ForegroundColor Cyan
$content = Get-Content -Path $Rot13File -Raw -Encoding UTF8
$decoded = Decode-Rot13 $content
Set-Content -Path $DecodedFile -Value $decoded -Encoding UTF8
Write-Host "[+] Wrote decoded dump to: $DecodedFile"

Write-Host "[3/4] Searching for COPY users section..." -ForegroundColor Cyan
$lines = Get-Content -Path $DecodedFile

# Find the COPY line related to users
$copyStart = ($lines | Select-String -Pattern 'COPY public\.users|COPY users' -CaseSensitive:$false).LineNumber
if (-not $copyStart) {
    # If not found, look for "COPY public.hfref" because this dump is ROT13 encoded
    $copyStart = ($lines | Select-String -Pattern 'COPY public\.hfref|COPY hfref' -CaseSensitive:$false).LineNumber
}

if (-not $copyStart) {
    Write-Host "[!] Could not find any user table COPY block." -ForegroundColor Red
    exit 1
}

# Get the data block
$block = @()
for ($i = $copyStart; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq '\.') { break }
    $block += $lines[$i]
}

# Parse column names
$headerLine = $lines[$copyStart - 1]
$columns = ($headerLine -replace 'COPY public\.[^\(]+\(|\) FROM stdin;','') -split ',' | ForEach-Object { $_.Trim() }
$pwdIndex = [Array]::IndexOf($columns, 'password_hash')
if ($pwdIndex -lt 0) { $pwdIndex = [Array]::IndexOf($columns, 'cnffjbeq_unfu') }

Write-Host "[4/4] Looking for user $TargetFirst $TargetLast..." -ForegroundColor Cyan
foreach ($row in $block) {
    if ($row -match $TargetFirst -and $row -match $TargetLast) {
        $fields = $row -split "`t"
        if ($pwdIndex -ge 0 -and $pwdIndex -lt $fields.Count) {
            $hash = $fields[$pwdIndex]
            Write-Host "`n=== RESULT ==="
            Write-Host ("Password hash for {0} {1}:`n{2}" -f $TargetFirst, $TargetLast, $hash) -ForegroundColor Green
            exit 0
        } else {
            Write-Host "[!] Password hash column not found for that row." -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host "[!] Could not find password hash for $TargetFirst $TargetLast." -ForegroundColor Red
exit 1
```
We get the hash as follows:  
`pbkdf2:sha256:600000$YQqIvcDipYLzzXPB$598fe450e5ac019cdd41b4b10c5c21515573ee63a8f4881f7d721fd74ee43d59`  
A3:  
`https://protoguard-asset-management.s3.us-east-2.amazonaws.com/db_backup.xyz, pbkdf2:sha256:600000$YQqIvcDipYLzzXPB$598fe450e5ac019cdd41b4b10c5c21515573ee63a8f4881f7d721fd74ee43d59 `  

  ---
  ## KEY4  
Q4:  Submit the public address of the database leak, including the name of the file.  

  As in Flag 3, the public address will be:  
A4:  

`https://protoguard-asset-management.s3.us-east-2.amazonaws.com/db_backup.xyz`  

-----

<img width="1509" height="174" alt="a1" src="https://github.com/user-attachments/assets/65941a9d-6286-4423-bb41-055f0e2a5685" />   

<img width="1519" height="148" alt="a2" src="https://github.com/user-attachments/assets/57c4540a-440b-4eb7-b8a9-b60e8466702b" />  

<img width="1520" height="183" alt="a3" src="https://github.com/user-attachments/assets/8eb2d598-3b26-4f64-81f6-28ab3738cfc5" />  

  <img width="1492" height="164" alt="a4" src="https://github.com/user-attachments/assets/94580ea9-a40f-48a8-959d-40b0367edb64" />  

  ----
  DONE!.


