// ======================================================
// SECURESIGN - DIGITAL SIGNATURE SYSTEM
// RSA-PSS + SHA-256
// ======================================================

// 1. APPLICATION STATE
let senderKeyPair = null;
let senderSignature = null;

let receiverPublicKey = null;
let receiverSignatureData = null;

let currentFingerprint = null;
let latestReport = null;

// 2. HTML ELEMENT HELPER
const $ = id => {
    const element = document.getElementById(id);
    if (!element) throw new Error("HTML element not found: " + id);
    return element;
};

// 3. ELEMENT REFERENCES
const generateKeysBtn = $("generateKeysBtn");
const signBtn = $("signBtn");
const verifyBtn = $("verifyBtn");
const tamperBtn = $("tamperBtn");

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

// 4. ARRAY BUFFER TO BASE64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

// 5. BASE64 TO ARRAY BUFFER
function base64ToArrayBuffer(base64) {
    const cleanBase64 = base64.trim();
    if (!cleanBase64) throw new Error("Base64 data is empty.");
    const binary = atob(cleanBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// 6. SHA-256 HASH GENERATION
async function generateHash(data) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, "0")).join("");
}

// 7. PUBLIC KEY FINGERPRINT
async function generateFingerprint(publicKeyBuffer) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", publicKeyBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, "0")).join(":").toUpperCase();
}

// 8. DOWNLOAD FILE
function downloadFile(filename, content) {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// 9. STATUS UPDATE
function setStatus(elementId, message, type = "neutral") {
    const element = $(elementId);
    element.textContent = message;
    element.className = "status " + type;
}

// 10. PROGRESS INDICATOR
function startProgress(trackId, barId) {
    const track = $(trackId);
    const bar = $(barId);
    track.classList.add("active");
    bar.classList.remove("complete");
    bar.style.width = "30%";
    setTimeout(() => { if (track.classList.contains("active")) bar.style.width = "70%"; }, 150);
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

// 11. RESET VERIFICATION REPORT
function resetReport() {
    latestReport = null;
    $("reportBanner").className = "report-banner neutral";
    $("reportHeading").textContent = "No Verification Performed";
    $("reportDescription").textContent = "The report will appear after verification.";
    $("reportValidity").textContent = "Pending";
    $("reportIntegrity").textContent = "Pending";
    $("reportTimestamp").textContent = "Not available";
    $("verificationResult").className = "verification-result neutral";
    $("verificationResult").innerHTML = `
        <div class="result-icon">?</div>
        <h3>Awaiting Verification</h3>
        <p>Import the required files to begin verification.</p>
    `;
    downloadReportBtn.disabled = true;
}

// 12. UPDATE KEY DETAILS
function updateKeyDetails(name, fingerprint) {
    $("reportSigner").textContent = name || "Not available";
    $("reportFingerprint").textContent = fingerprint || "Not available";
}

// 13. CLEAR RECEIVER DATA
function clearReceiverData() {
    receiverPublicKey = null;
    receiverSignatureData = null;
    $("publicKeyFile").value = "";
    $("signatureFile").value = "";
    $("expectedFingerprint").value = "";
    receiverPublicKeyOutput.value = "";
    receiverSignatureOutput.value = "";
    $("receiverAlgorithm").textContent = "Not available";
    $("receiverKeySize").textContent = "Not available";
    $("receiverFingerprint").textContent = "Not available";
    setStatus("publicKeyStatus", "Public key not imported.", "neutral");
    setStatus("signatureStatus", "Signature not imported.", "neutral");
    resetReport();
}

// 14. RSA KEY GENERATION
generateKeysBtn.addEventListener("click", async () => {
    try {
        if (!crypto.subtle) throw new Error("Web Crypto API unavailable. Run through localhost.");
        generateKeysBtn.disabled = true;
        startProgress("keyProgress", "keyProgressBar");
        setStatus("keyStatus", "Generating RSA-2048 key pair...", "neutral");

        const newKeyPair = await crypto.subtle.generateKey(
            { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            false, ["sign", "verify"]
        );

        const exportedPublicKey = await crypto.subtle.exportKey("spki", newKeyPair.publicKey);
        const publicKeyBase64 = arrayBufferToBase64(exportedPublicKey);
        const fingerprint = await generateFingerprint(exportedPublicKey);

        senderKeyPair = newKeyPair;
        currentFingerprint = fingerprint;
        senderSignature = null;

        publicKeyOutput.value = publicKeyBase64;
        signatureOutput.value = "";
        hashOutput.textContent = "Hash will appear here...";

        downloadPublicKeyBtn.disabled = false;
        downloadSignatureBtn.disabled = true;

        clearReceiverData();
        updateKeyDetails($("signerName").value.trim() || "Demo Sender", fingerprint);

        setStatus("keyStatus", "RSA-2048 key pair generated successfully!", "success");
        setStatus("signStatus", "Waiting for message signing.", "neutral");
        setStatus("downloadStatus", "Generate a signature before downloading.", "neutral");

        finishProgress("keyProgress", "keyProgressBar");
    } catch (error) {
        console.error(error);
        setStatus("keyStatus", "Key generation failed: " + error.message, "error");
        clearProgress("keyProgress", "keyProgressBar");
    } finally {
        generateKeysBtn.disabled = false;
    }
});

// 15. DIGITAL SIGNATURE GENERATION
signBtn.addEventListener("click", async () => {
    try {
        if (!senderKeyPair) return alert("Please generate RSA keys first!");
        const message = senderMessage.value;
        if (!message.trim()) return alert("Please enter a message!");

        signBtn.disabled = true;
        startProgress("signProgress", "signProgressBar");
        setStatus("signStatus", "Generating SHA-256 hash and digital signature...", "neutral");

        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hash = await generateHash(data);
        hashOutput.textContent = hash;

        const signature = await crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            senderKeyPair.privateKey,
            data
        );

        senderSignature = signature;
        const signatureBase64 = arrayBufferToBase64(signature);
        signatureOutput.value = signatureBase64;

        downloadSignatureBtn.disabled = false;
        receiverMessage.value = message;
        clearReceiverData();

        setStatus("signStatus", "Digital signature generated successfully!", "success");
        setStatus("downloadStatus", "Public key and digital signature are ready for download.", "success");
        finishProgress("signProgress", "signProgressBar");
    } catch (error) {
        console.error(error);
        senderSignature = null;
        downloadSignatureBtn.disabled = true;
        setStatus("signStatus", "Signing failed: " + error.message, "error");
        clearProgress("signProgress", "signProgressBar");
    } finally {
        signBtn.disabled = false;
    }
});

// 16. DOWNLOAD BUTTONS
downloadPublicKeyBtn.addEventListener("click", () => {
    if (!senderKeyPair) return alert("Generate RSA keys first!");
    downloadFile("sender_public_key.txt", publicKeyOutput.value);
    setStatus("downloadStatus", "Public key downloaded successfully.", "success");
});

downloadSignatureBtn.addEventListener("click", () => {
    if (!senderSignature) return alert("Generate a digital signature first!");
    downloadFile("digital_signature.txt", signatureOutput.value);
    setStatus("downloadStatus", "Digital signature downloaded successfully.", "success");
});

// 17. AUTO-FILL FEATURE
$("autoFillBtn").addEventListener("click", () => {
    if (!senderKeyPair || !senderSignature) {
        alert("Please generate keys and a signature in the Sender Panel first!");
        return;
    }
    
    receiverMessage.value = senderMessage.value;
    receiverPublicKeyOutput.value = publicKeyOutput.value;
    receiverSignatureOutput.value = signatureOutput.value;
    
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyOutput.value);
    crypto.subtle.importKey("spki", publicKeyBuffer, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"])
        .then(importedKey => {
            receiverPublicKey = importedKey;
            $("receiverAlgorithm").textContent = "RSA-PSS";
            $("receiverKeySize").textContent = "2048 bits";
            $("receiverFingerprint").textContent = currentFingerprint;
            setStatus("publicKeyStatus", "Public key auto-filled successfully!", "success");
        });

    receiverSignatureData = base64ToArrayBuffer(signatureOutput.value);
    setStatus("signatureStatus", "Digital signature auto-filled successfully!", "success");
    
    $("expectedFingerprint").value = currentFingerprint; 
    resetReport();
});

// 18. RECEIVER IMPORTS PUBLIC KEY (FILE)
$("publicKeyFile").addEventListener("change", async event => {
    try {
        const file = event.target.files[0];
        receiverPublicKey = null;
        receiverPublicKeyOutput.value = "";
        if (!file) return;

        setStatus("publicKeyStatus", "Importing public key...", "neutral");
        const publicKeyBase64 = (await file.text()).trim();
        const publicKeyBuffer = base64ToArrayBuffer(publicKeyBase64);
        const fingerprint = await generateFingerprint(publicKeyBuffer);

        const importedKey = await crypto.subtle.importKey(
            "spki", publicKeyBuffer, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]
        );

        if (importedKey.algorithm.modulusLength !== 2048) throw new Error("Expected an RSA-2048 public key.");

        receiverPublicKey = importedKey;
        receiverPublicKeyOutput.value = publicKeyBase64;
        $("receiverAlgorithm").textContent = "RSA-PSS";
        $("receiverKeySize").textContent = importedKey.algorithm.modulusLength + " bits";
        $("receiverFingerprint").textContent = fingerprint;

        const expectedFp = $("expectedFingerprint").value.trim().replace(/:/g, '').toUpperCase();
        const actualFp = fingerprint.replace(/:/g, '').toUpperCase();

        if (expectedFp && expectedFp !== actualFp) {
            setStatus("publicKeyStatus", "⚠ Fingerprint mismatch! This key does not match the expected sender.", "error");
        } else {
            setStatus("publicKeyStatus", "Public key imported successfully!", "success");
        }
        resetReport();
    } catch (error) {
        receiverPublicKey = null;
        receiverPublicKeyOutput.value = "";
        $("receiverAlgorithm").textContent = "Not available";
        $("receiverKeySize").textContent = "Not available";
        $("receiverFingerprint").textContent = "Not available";
        setStatus("publicKeyStatus", "Public key import failed: " + error.message, "error");
    }
});

// 19. RECEIVER IMPORTS DIGITAL SIGNATURE (FILE)
$("signatureFile").addEventListener("change", async event => {
    try {
        const file = event.target.files[0];
        receiverSignatureData = null;
        receiverSignatureOutput.value = "";
        if (!file) return;

        setStatus("signatureStatus", "Reading digital signature...", "neutral");
        const signatureBase64 = (await file.text()).trim();
        const signatureBuffer = base64ToArrayBuffer(signatureBase64);

        if (signatureBuffer.byteLength !== 256) throw new Error("Invalid signature length for RSA-2048.");

        receiverSignatureData = signatureBuffer;
        receiverSignatureOutput.value = signatureBase64;
        setStatus("signatureStatus", "Digital signature imported successfully!", "success");
        resetReport();
    } catch (error) {
        receiverSignatureData = null;
        receiverSignatureOutput.value = "";
        setStatus("signatureStatus", "Signature import failed: " + error.message, "error");
    }
});

// 20. UPDATE VERIFICATION REPORT
function updateVerificationReport(isValid, fingerprint) {
    const timestamp = new Date().toLocaleString();
    const validity = isValid ? "VALID" : "INVALID";
    const integrity = isValid ? "VERIFIED" : "NOT VERIFIED";

    $("reportBanner").className = "report-banner " + (isValid ? "valid" : "invalid");
    $("reportBanner").querySelector(".report-banner-icon").textContent = isValid ? "✓" : "✕";
    $("reportHeading").textContent = isValid ? "Digital Signature Successfully Verified" : "Digital Signature Verification Failed";
    $("reportDescription").textContent = isValid 
        ? "The signature is valid for the received message and imported public key." 
        : "The signature could not be verified against the received message and public key.";

    $("reportValidity").textContent = validity;
    $("reportIntegrity").textContent = integrity;
    $("reportTimestamp").textContent = timestamp;

    latestReport = {
        result: validity, messageIntegrity: integrity,
        signer: $("signerName").value.trim() || "Unknown / Not provided",
        signatureAlgorithm: "RSA-PSS", hashAlgorithm: "SHA-256", keySize: "2048 bits",
        fingerprint: fingerprint, certificateTrust: "Not validated - no trusted CA certificate supplied",
        timestamp: timestamp
    };
    downloadReportBtn.disabled = false;
}

// 21. FEATURE: TAMPER BUTTON
tamperBtn.addEventListener("click", () => {
    if (!receiverMessage.value) {
        alert("There is no message to tamper with. Auto-fill or type a message first.");
        return;
    }
    const firstChar = receiverMessage.value.charAt(0);
    const tamperedChar = firstChar === firstChar.toUpperCase() ? firstChar.toLowerCase() : firstChar.toUpperCase();
    receiverMessage.value = tamperedChar + receiverMessage.value.slice(1);
    
    receiverMessage.style.backgroundColor = "rgba(239, 68, 68, 0.1)";
    receiverMessage.style.borderColor = "#ef4444";
    setTimeout(() => {
        receiverMessage.style.backgroundColor = "";
        receiverMessage.style.borderColor = "";
    }, 800);
});

// 22. RECEIVER VERIFICATION
verifyBtn.addEventListener("click", async () => {
    try {
        if (!receiverPublicKey) return alert("Import the sender's public key first!");
        if (!receiverSignatureData) return alert("Import the digital signature first!");
        const message = receiverMessage.value;
        if (!message.trim()) return alert("Enter the received message!");

        verifyBtn.disabled = true;
        startProgress("verifyProgress", "verifyProgressBar");
        
        const result = $("verificationResult");
        result.className = "verification-result neutral";
        result.innerHTML = `<div class="result-icon">...</div><h3>Verifying Signature</h3><p>Checking the received message and digital signature.</p>`;

        const encoder = new TextEncoder();
        const data = encoder.encode(message);

        const isValid = await crypto.subtle.verify(
            { name: "RSA-PSS", saltLength: 32 },
            receiverPublicKey, receiverSignatureData, data
        );

        if (isValid) {
            result.className = "verification-result valid";
            result.innerHTML = `<div class="result-icon">✓</div><h3>SIGNATURE VALID</h3><p>The received message matches the digital signature generated by the corresponding private key.</p>`;
        } else {
            result.className = "verification-result invalid";
            result.innerHTML = `<div class="result-icon">✕</div><h3>SIGNATURE INVALID</h3><p>The message may have been modified, or the signature does not match the imported public key.</p>`;
        }

        updateVerificationReport(isValid, $("receiverFingerprint").textContent);
        finishProgress("verifyProgress", "verifyProgressBar");
    } catch (error) {
        console.error(error);
        const result = $("verificationResult");
        result.className = "verification-result invalid";
        result.innerHTML = `<div class="result-icon">!</div><h3>VERIFICATION ERROR</h3><p>${error.message}</p>`;
        clearProgress("verifyProgress", "verifyProgressBar");
    } finally {
        verifyBtn.disabled = false;
    }
});

// 23. DOWNLOAD VERIFICATION REPORT
downloadReportBtn.addEventListener("click", () => {
    if (!latestReport) return alert("Perform signature verification first!");
    const reportText = `
DIGITAL SIGNATURE VERIFICATION REPORT
=====================================
Verification Result: ${latestReport.result}
Message Integrity: ${latestReport.messageIntegrity}
Signer Label: ${latestReport.signer}
Signature Algorithm: ${latestReport.signatureAlgorithm}
Hash Algorithm: ${latestReport.hashAlgorithm}
RSA Key Size: ${latestReport.keySize}
Public Key Fingerprint: ${latestReport.fingerprint}
Certificate Trust: ${latestReport.certificateTrust}
Verification Timestamp: ${latestReport.timestamp}

=====================================
Note: This is an educational cryptographic demonstration.
The verification result confirms signature validity against
the imported public key. It does not establish the real-world
identity of the signer or validate a certificate chain.
`;
    downloadFile("digital_signature_verification_report.txt", reportText);
});

// 24. RESET / NEW TRANSACTION
$("resetBtn").addEventListener("click", () => {
    if (!confirm("Start a new transaction? Current keys and signatures will be cleared.")) return;

    senderKeyPair = null; senderSignature = null;
    receiverPublicKey = null; receiverSignatureData = null;
    currentFingerprint = null; latestReport = null;

    $("signerName").value = "Demo Sender";
    senderMessage.value = "Hello, this is my digital signature demonstration.";
    publicKeyOutput.value = ""; signatureOutput.value = "";
    hashOutput.textContent = "Hash will appear here...";
    receiverMessage.value = ""; receiverPublicKeyOutput.value = ""; receiverSignatureOutput.value = "";
    $("expectedFingerprint").value = "";

    $("publicKeyFile").value = ""; $("signatureFile").value = "";
    $("receiverAlgorithm").textContent = "Not available";
    $("receiverKeySize").textContent = "Not available";
    $("receiverFingerprint").textContent = "Not available";
    updateKeyDetails("Not available", "Not available");

    downloadPublicKeyBtn.disabled = true;
    downloadSignatureBtn.disabled = true;
    downloadReportBtn.disabled = true;

    setStatus("keyStatus", "No keys generated yet.", "neutral");
    setStatus("signStatus", "Waiting for message signing.", "neutral");
    setStatus("downloadStatus", "Generate keys and signature before downloading.", "neutral");
    setStatus("publicKeyStatus", "Public key not imported.", "neutral");
    setStatus("signatureStatus", "Signature not imported.", "neutral");

    resetReport();
    clearProgress("keyProgress", "keyProgressBar");
    clearProgress("signProgress", "signProgressBar");
    clearProgress("verifyProgress", "verifyProgressBar");

    generateKeysBtn.disabled = false;
    signBtn.disabled = false;
    verifyBtn.disabled = false;

    alert("New transaction started successfully!");
});

// ======================================================
// 25. THEME TOGGLE (DARK / LIGHT MODE) - FIXED
// ======================================================
const themeToggleBtn = document.getElementById("themeToggle");

// Check local storage for saved theme on load
if (localStorage.getItem("theme") === "light") {
    document.body.classList.add("light-theme");
    themeToggleBtn.textContent = "☀️";
} else {
    document.body.classList.remove("light-theme");
    themeToggleBtn.textContent = "🌙";
}

themeToggleBtn.addEventListener("click", () => {
    document.body.classList.toggle("light-theme");
    
    if (document.body.classList.contains("light-theme")) {
        localStorage.setItem("theme", "light");
        themeToggleBtn.textContent = "☀️";
    } else {
        localStorage.setItem("theme", "dark");
        themeToggleBtn.textContent = "🌙";
    }
});