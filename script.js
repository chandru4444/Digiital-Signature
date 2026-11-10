
// ======================================================
// SECURESIGN - DIGITAL SIGNATURE SYSTEM
// RSA-PSS + SHA-256
// ======================================================


// ======================================================
// 1. APPLICATION STATE
// ======================================================

let senderKeyPair = null;
let senderSignature = null;

let receiverPublicKey = null;
let receiverSignatureData = null;

let currentFingerprint = null;
let latestReport = null;


// ======================================================
// 2. HTML ELEMENT HELPER
// ======================================================

const $ = id => {

    const element = document.getElementById(id);

    if (!element) {
        throw new Error("HTML element not found: " + id);
    }

    return element;
};


// ======================================================
// 3. ELEMENT REFERENCES
// ======================================================

const generateKeysBtn = $("generateKeysBtn");
const signBtn = $("signBtn");
const verifyBtn = $("verifyBtn");

const downloadPublicKeyBtn = $("downloadPublicKeyBtn");
const downloadSignatureBtn = $("downloadSignatureBtn");
const downloadReportBtn = $("downloadReportBtn");

const senderMessage = $("senderMessage");
const receiverMessage = $("receiverMessage");

const publicKeyOutput = $("publicKey");
const signatureOutput = $("signatureOutput");
const hashOutput = $("hashOutput");

const receiverPublicKeyOutput = $("receiverPublicKey");
const receiverSignatureOutput = $("receiverSignature");


// ======================================================
// 4. ARRAY BUFFER TO BASE64
// ======================================================

function arrayBufferToBase64(buffer) {

    const bytes = new Uint8Array(buffer);

    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}


// ======================================================
// 5. BASE64 TO ARRAY BUFFER
// ======================================================

function base64ToArrayBuffer(base64) {

    const cleanBase64 = base64.trim();

    if (!cleanBase64) {
        throw new Error("Base64 data is empty.");
    }

    const binary = atob(cleanBase64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}


// ======================================================
// 6. SHA-256 HASH GENERATION
// ======================================================

async function generateHash(data) {

    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        data
    );

    const hashArray = Array.from(
        new Uint8Array(hashBuffer)
    );

    return hashArray
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}


// ======================================================
// 7. PUBLIC KEY FINGERPRINT
// ======================================================

async function generateFingerprint(publicKeyBuffer) {

    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        publicKeyBuffer
    );

    const hashArray = Array.from(
        new Uint8Array(hashBuffer)
    );

    return hashArray
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join(":")
        .toUpperCase();
}


// ======================================================
// 8. DOWNLOAD FILE
// ======================================================

function downloadFile(filename, content) {

    const blob = new Blob(
        [content],
        { type: "text/plain;charset=utf-8" }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);

    link.click();

    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}


// ======================================================
// 9. STATUS UPDATE
// ======================================================

function setStatus(elementId, message, type = "neutral") {

    const element = $(elementId);

    element.textContent = message;
    element.className = "status " + type;
}


// ======================================================
// 10. PROGRESS INDICATOR
// ======================================================

function startProgress(trackId, barId) {

    const track = $(trackId);
    const bar = $(barId);

    track.classList.add("active");

    bar.classList.remove("complete");
    bar.style.width = "30%";

    setTimeout(() => {

        if (track.classList.contains("active")) {
            bar.style.width = "70%";
        }

    }, 150);
}


function finishProgress(trackId, barId) {

    const track = $(trackId);
    const bar = $(barId);

    bar.style.width = "100%";
    bar.classList.add("complete");

    setTimeout(() => {

        track.classList.remove("active");

        bar.classList.remove("complete");
        bar.style.width = "0%";

    }, 1000);
}


function clearProgress(trackId, barId) {

    $(trackId).classList.remove("active");

    $(barId).classList.remove("complete");
    $(barId).style.width = "0%";
}


// ======================================================
// 11. RESET VERIFICATION REPORT
// ======================================================

function resetReport() {

    latestReport = null;

    $("reportBanner").className = "report-banner neutral";

    $("reportHeading").textContent =
        "No Verification Performed";

    $("reportDescription").textContent =
        "The report will appear after verification.";

    $("reportValidity").textContent = "Pending";

    $("reportIntegrity").textContent = "Pending";

    $("reportTimestamp").textContent = "Not available";

    $("verificationResult").className =
        "verification-result neutral";

    $("verificationResult").innerHTML = `
        <div class="result-icon">?</div>
        <h3>Awaiting Verification</h3>
        <p>Import the required files to begin verification.</p>
    `;

    downloadReportBtn.disabled = true;
}


// ======================================================
// 12. UPDATE KEY DETAILS
// ======================================================

function updateKeyDetails(name, fingerprint) {

    $("reportSigner").textContent =
        name || "Not available";

    $("reportFingerprint").textContent =
        fingerprint || "Not available";
}


// ======================================================
// 13. CLEAR RECEIVER DATA
// ======================================================

function clearReceiverData() {

    receiverPublicKey = null;
    receiverSignatureData = null;

    $("publicKeyFile").value = "";
    $("signatureFile").value = "";

    receiverPublicKeyOutput.value = "";
    receiverSignatureOutput.value = "";

    $("receiverAlgorithm").textContent = "Not available";
    $("receiverKeySize").textContent = "Not available";
    $("receiverFingerprint").textContent = "Not available";

    setStatus(
        "publicKeyStatus",
        "Public key not imported.",
        "neutral"
    );

    setStatus(
        "signatureStatus",
        "Signature not imported.",
        "neutral"
    );

    resetReport();
}


// ======================================================
// 14. RSA KEY GENERATION
// ======================================================

generateKeysBtn.addEventListener("click", async () => {

    try {

        if (!crypto.subtle) {
            throw new Error(
                "Web Crypto API unavailable. Run through localhost using Live Server."
            );
        }

        generateKeysBtn.disabled = true;

        startProgress(
            "keyProgress",
            "keyProgressBar"
        );

        setStatus(
            "keyStatus",
            "Generating RSA-2048 key pair...",
            "neutral"
        );

        // Generate RSA key pair

        const newKeyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-PSS",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            false,
            ["sign", "verify"]
        );

        // Export public key only

        const exportedPublicKey =
            await crypto.subtle.exportKey(
                "spki",
                newKeyPair.publicKey
            );

        const publicKeyBase64 =
            arrayBufferToBase64(exportedPublicKey);

        // Generate fingerprint

        const fingerprint =
            await generateFingerprint(exportedPublicKey);

        // Save new key pair

        senderKeyPair = newKeyPair;

        currentFingerprint = fingerprint;

        senderSignature = null;

        // Display public key

        publicKeyOutput.value = publicKeyBase64;

        // Clear previous signature

        signatureOutput.value = "";

        hashOutput.textContent =
            "Hash will appear here...";

        // Update buttons

        downloadPublicKeyBtn.disabled = false;

        downloadSignatureBtn.disabled = true;

        // Clear old receiver transaction

        clearReceiverData();

        // Update key details

        updateKeyDetails(
            $("signerName").value.trim() || "Demo Sender",
            fingerprint
        );

        setStatus(
            "keyStatus",
            "RSA-2048 key pair generated successfully!",
            "success"
        );

        setStatus(
            "signStatus",
            "Waiting for message signing.",
            "neutral"
        );

        setStatus(
            "downloadStatus",
            "Generate a signature before downloading.",
            "neutral"
        );

        finishProgress(
            "keyProgress",
            "keyProgressBar"
        );

    }

    catch (error) {

        console.error(error);

        setStatus(
            "keyStatus",
            "Key generation failed: " + error.message,
            "error"
        );

        clearProgress(
            "keyProgress",
            "keyProgressBar"
        );

    }

    finally {

        generateKeysBtn.disabled = false;

    }

});


// ======================================================
// 15. DIGITAL SIGNATURE GENERATION
// ======================================================

signBtn.addEventListener("click", async () => {

    try {

        if (!senderKeyPair) {

            alert("Please generate RSA keys first!");

            return;

        }

        const message = senderMessage.value;

        if (!message.trim()) {

            alert("Please enter a message!");

            return;

        }

        signBtn.disabled = true;

        startProgress(
            "signProgress",
            "signProgressBar"
        );

        setStatus(
            "signStatus",
            "Generating SHA-256 hash and digital signature...",
            "neutral"
        );

        // Convert message into bytes

        const encoder = new TextEncoder();

        const data = encoder.encode(message);

        // Calculate SHA-256 hash for display

        const hash = await generateHash(data);

        hashOutput.textContent = hash;

        // Sign using sender's PRIVATE KEY

        const signature = await crypto.subtle.sign(
            {
                name: "RSA-PSS",
                saltLength: 32
            },
            senderKeyPair.privateKey,
            data
        );

        senderSignature = signature;

        // Convert signature into Base64

        const signatureBase64 =
            arrayBufferToBase64(signature);

        signatureOutput.value = signatureBase64;

        // Enable download

        downloadSignatureBtn.disabled = false;

        // Automatically copy original message into receiver panel
        // This is only a convenience for the same-browser demonstration.

        receiverMessage.value = message;

        // Remove previous imports and verification results

        clearReceiverData();

        setStatus(
            "signStatus",
            "Digital signature generated successfully!",
            "success"
        );

        setStatus(
            "downloadStatus",
            "Public key and digital signature are ready for download.",
            "success"
        );

        finishProgress(
            "signProgress",
            "signProgressBar"
        );

    }

    catch (error) {

        console.error(error);

        senderSignature = null;

        downloadSignatureBtn.disabled = true;

        setStatus(
            "signStatus",
            "Signing failed: " + error.message,
            "error"
        );

        clearProgress(
            "signProgress",
            "signProgressBar"
        );

    }

    finally {

        signBtn.disabled = false;

    }

});


// ======================================================
// 16. DOWNLOAD PUBLIC KEY
// ======================================================

downloadPublicKeyBtn.addEventListener("click", () => {

    if (!senderKeyPair) {

        alert("Generate RSA keys first!");

        return;

    }

    downloadFile(
        "sender_public_key.txt",
        publicKeyOutput.value
    );

    setStatus(
        "downloadStatus",
        "Public key downloaded successfully.",
        "success"
    );

});


// ======================================================
// 17. DOWNLOAD DIGITAL SIGNATURE
// ======================================================

downloadSignatureBtn.addEventListener("click", () => {

    if (!senderSignature) {

        alert("Generate a digital signature first!");

        return;

    }

    downloadFile(
        "digital_signature.txt",
        signatureOutput.value
    );

    setStatus(
        "downloadStatus",
        "Digital signature downloaded successfully.",
        "success"
    );

});


// ======================================================
// 18. RECEIVER IMPORTS PUBLIC KEY
// ======================================================

$("publicKeyFile").addEventListener("change", async event => {

    try {

        const file = event.target.files[0];

        receiverPublicKey = null;

        receiverPublicKeyOutput.value = "";

        if (!file) return;

        if (file.size > 100000) {
            throw new Error("Public key file is too large.");
        }

        setStatus(
            "publicKeyStatus",
            "Importing public key...",
            "neutral"
        );

        const publicKeyBase64 =
            (await file.text()).trim();

        if (!publicKeyBase64) {
            throw new Error("Public key file is empty.");
        }

        // Decode Base64

        const publicKeyBuffer =
            base64ToArrayBuffer(publicKeyBase64);

        // Check RSA public key fingerprint

        const fingerprint =
            await generateFingerprint(publicKeyBuffer);

        // Import sender's public key

        const importedKey = await crypto.subtle.importKey(
            "spki",
            publicKeyBuffer,
            {
                name: "RSA-PSS",
                hash: "SHA-256"
            },
            false,
            ["verify"]
        );

        // Check key size

        if (
            importedKey.algorithm.modulusLength !== 2048
        ) {
            throw new Error("Expected an RSA-2048 public key.");
        }

        receiverPublicKey = importedKey;

        receiverPublicKeyOutput.value =
            publicKeyBase64;

        // Display key information

        $("receiverAlgorithm").textContent =
            "RSA-PSS";

        $("receiverKeySize").textContent =
            importedKey.algorithm.modulusLength + " bits";

        $("receiverFingerprint").textContent =
            fingerprint;

        setStatus(
            "publicKeyStatus",
            "Public key imported successfully!",
            "success"
        );

        resetReport();

    }

    catch (error) {

        receiverPublicKey = null;

        receiverPublicKeyOutput.value = "";

        $("receiverAlgorithm").textContent = "Not available";

        $("receiverKeySize").textContent = "Not available";

        $("receiverFingerprint").textContent = "Not available";

        console.error(error);

        setStatus(
            "publicKeyStatus",
            "Public key import failed: " + error.message,
            "error"
        );

    }

});


// ======================================================
// 19. RECEIVER IMPORTS DIGITAL SIGNATURE
// ======================================================

$("signatureFile").addEventListener("change", async event => {

    try {

        const file = event.target.files[0];

        receiverSignatureData = null;

        receiverSignatureOutput.value = "";

        if (!file) return;

        if (file.size > 100000) {
            throw new Error("Signature file is too large.");
        }

        setStatus(
            "signatureStatus",
            "Reading digital signature...",
            "neutral"
        );

        const signatureBase64 =
            (await file.text()).trim();

        if (!signatureBase64) {
            throw new Error("Signature file is empty.");
        }

        const signatureBuffer =
            base64ToArrayBuffer(signatureBase64);

        // RSA-2048 signature must be 256 bytes

        if (signatureBuffer.byteLength !== 256) {

            throw new Error(
                "Invalid signature length for RSA-2048."
            );

        }

        receiverSignatureData = signatureBuffer;

        receiverSignatureOutput.value =
            signatureBase64;

        setStatus(
            "signatureStatus",
            "Digital signature imported successfully!",
            "success"
        );

        resetReport();

    }

    catch (error) {

        receiverSignatureData = null;

        receiverSignatureOutput.value = "";

        console.error(error);

        setStatus(
            "signatureStatus",
            "Signature import failed: " + error.message,
            "error"
        );

    }

});


// ======================================================
// 20. UPDATE VERIFICATION REPORT
// ======================================================

function updateVerificationReport(isValid, fingerprint) {

    const timestamp = new Date().toLocaleString();

    const validity = isValid ? "VALID" : "INVALID";

    const integrity = isValid
        ? "VERIFIED"
        : "NOT VERIFIED";

    // Update banner

    $("reportBanner").className =
        "report-banner " + (isValid ? "valid" : "invalid");

    $("reportBanner").querySelector(
        ".report-banner-icon"
    ).textContent = isValid ? "✓" : "✕";

    $("reportHeading").textContent =
        isValid
            ? "Digital Signature Successfully Verified"
            : "Digital Signature Verification Failed";

    $("reportDescription").textContent =
        isValid
            ? "The signature is valid for the received message and imported public key."
            : "The signature could not be verified against the received message and public key.";

    // Update report fields

    $("reportValidity").textContent = validity;

    $("reportIntegrity").textContent = integrity;

    $("reportTimestamp").textContent = timestamp;

    latestReport = {

        result: validity,

        messageIntegrity: integrity,

        signer:
            $("signerName").value.trim() || "Unknown / Not provided",

        signatureAlgorithm: "RSA-PSS",

        hashAlgorithm: "SHA-256",

        keySize: "2048 bits",

        fingerprint: fingerprint,

        certificateTrust:
            "Not validated - no trusted CA certificate supplied",

        timestamp: timestamp

    };

    downloadReportBtn.disabled = false;

}


// ======================================================
// 21. RECEIVER VERIFICATION
// ======================================================

verifyBtn.addEventListener("click", async () => {

    try {

        if (!receiverPublicKey) {

            alert("Import the sender's public key first!");

            return;

        }

        if (!receiverSignatureData) {

            alert("Import the digital signature first!");

            return;

        }

        const message = receiverMessage.value;

        if (!message.trim()) {

            alert("Enter the received message!");

            return;

        }

        verifyBtn.disabled = true;

        startProgress(
            "verifyProgress",
            "verifyProgressBar"
        );

        const result = $("verificationResult");

        result.className =
            "verification-result neutral";

        result.innerHTML = `
            <div class="result-icon">...</div>
            <h3>Verifying Signature</h3>
            <p>Checking the received message and digital signature.</p>
        `;

        // Convert received message into bytes

        const encoder = new TextEncoder();

        const data = encoder.encode(message);

        // Verify using RECEIVER'S IMPORTED PUBLIC KEY

        const isValid = await crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 32
            },
            receiverPublicKey,
            receiverSignatureData,
            data
        );

        if (isValid) {

            result.className =
                "verification-result valid";

            result.innerHTML = `
                <div class="result-icon">✓</div>
                <h3>SIGNATURE VALID</h3>
                <p>
                    The received message matches the digital signature
                    generated by the corresponding private key.
                </p>
            `;

        }

        else {

            result.className =
                "verification-result invalid";

            result.innerHTML = `
                <div class="result-icon">✕</div>
                <h3>SIGNATURE INVALID</h3>
                <p>
                    The message may have been modified, or the signature
                    does not match the imported public key.
                </p>
            `;

        }

        // Update verification report

        updateVerificationReport(
            isValid,
            $("receiverFingerprint").textContent
        );

        finishProgress(
            "verifyProgress",
            "verifyProgressBar"
        );

    }

    catch (error) {

        console.error(error);

        const result = $("verificationResult");

        result.className =
            "verification-result invalid";

        result.innerHTML = `
            <div class="result-icon">!</div>
            <h3>VERIFICATION ERROR</h3>
            <p>${error.message}</p>
        `;

        clearProgress(
            "verifyProgress",
            "verifyProgressBar"
        );

    }

    finally {

        verifyBtn.disabled = false;

    }

});


// ======================================================
// 22. DOWNLOAD VERIFICATION REPORT
// ======================================================

downloadReportBtn.addEventListener("click", () => {

    if (!latestReport) {

        alert("Perform signature verification first!");

        return;

    }

    const reportText = `
DIGITAL SIGNATURE VERIFICATION REPORT
=====================================

Verification Result: ${latestReport.result}

Message Integrity: ${latestReport.messageIntegrity}

Signer Label: ${latestReport.signer}

Signature Algorithm: ${latestReport.signatureAlgorithm}

Hash Algorithm: ${latestReport.hashAlgorithm}

RSA Key Size: ${latestReport.keySize}

Public Key Fingerprint:
${latestReport.fingerprint}

Certificate Trust:
${latestReport.certificateTrust}

Verification Timestamp:
${latestReport.timestamp}

=====================================

Note:
This is an educational cryptographic demonstration.
The verification result confirms signature validity against
the imported public key. It does not establish the real-world
identity of the signer or validate a certificate chain.
`;

    downloadFile(
        "digital_signature_verification_report.txt",
        reportText
    );

});


// ======================================================
// 23. RESET / NEW TRANSACTION
// ======================================================

$("resetBtn").addEventListener("click", () => {

    const confirmed = confirm(
        "Start a new transaction? Current keys and signatures will be cleared."
    );

    if (!confirmed) return;

    // Clear cryptographic state

    senderKeyPair = null;
    senderSignature = null;

    receiverPublicKey = null;
    receiverSignatureData = null;

    currentFingerprint = null;
    latestReport = null;

    // Clear sender fields

    $("signerName").value = "Demo Sender";

    senderMessage.value =
        "Hello, this is my digital signature demonstration.";

    publicKeyOutput.value = "";

    signatureOutput.value = "";

    hashOutput.textContent =
        "Hash will appear here...";

    // Clear receiver fields

    receiverMessage.value = "";

    receiverPublicKeyOutput.value = "";

    receiverSignatureOutput.value = "";

    $("publicKeyFile").value = "";

    $("signatureFile").value = "";

    // Reset key information

    $("receiverAlgorithm").textContent = "Not available";

    $("receiverKeySize").textContent = "Not available";

    $("receiverFingerprint").textContent = "Not available";

    updateKeyDetails("Not available", "Not available");

    // Disable download buttons

    downloadPublicKeyBtn.disabled = true;

    downloadSignatureBtn.disabled = true;

    downloadReportBtn.disabled = true;

    // Reset statuses

    setStatus(
        "keyStatus",
        "No keys generated yet.",
        "neutral"
    );

    setStatus(
        "signStatus",
        "Waiting for message signing.",
        "neutral"
    );

    setStatus(
        "downloadStatus",
        "Generate keys and signature before downloading.",
        "neutral"
    );

    setStatus(
        "publicKeyStatus",
        "Public key not imported.",
        "neutral"
    );

    setStatus(
        "signatureStatus",
        "Signature not imported.",
        "neutral"
    );

    // Reset report

    resetReport();

    // Reset progress

    clearProgress("keyProgress", "keyProgressBar");

    clearProgress("signProgress", "signProgressBar");

    clearProgress("verifyProgress", "verifyProgressBar");

    // Enable buttons

    generateKeysBtn.disabled = false;

    signBtn.disabled = false;

    verifyBtn.disabled = false;

    alert("New transaction started successfully!");

});


// ======================================================
// 24. APPLICATION INITIALIZATION
// ======================================================

console.log("--------------------------------");

console.log("SecureSign Digital Signature System");

console.log("RSA-PSS + SHA-256");

console.log("Web Crypto API available:", !!crypto.subtle);

console.log("Application initialized successfully.");

console.log("--------------------------------");
