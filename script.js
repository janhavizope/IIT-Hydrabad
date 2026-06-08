async function uploadAPK(file) {
    try {
        const formData = new FormData();

        // IMPORTANT: key MUST be "file"
        formData.append("file", file);

        const response = await fetch("http://127.0.0.1:8000/predict-apk", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            throw new Error("Upload failed");
        }

        const data = await response.json();
        console.log("Response:", data);

        return data;

    } catch (error) {
        console.error("Error uploading APK:", error);
        alert("Network error occurred during upload");
    }
}