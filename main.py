from fastapi import FastAPI, UploadFile, File
import os
import uvicorn
import multiprocessing
import client

app = FastAPI()
UPLOAD_DIR = "cloud_storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload/")
async def upload(file: UploadFile = File(...)):
    path = os.path.join(UPLOAD_DIR, file.filename)
    with open(path, "wb") as f:
        f.write(await file.read())
    return {"status": "success", "filename": file.filename}

@app.get("/download/{filename}")
async def download(filename: str):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return {"error": "file not found"}
    with open(path, "rb") as f:
        return {"filename": filename, "data": f.read().hex()}


def run_server():
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="error"
    )


if __name__ == "__main__":
    # Start server in a separate process
    server_proc = multiprocessing.Process(target=run_server, daemon=True)
    server_proc.start()

    try:
        # Run client in main process
        client.start_client()
    finally:
        # If client exits, stop the server
        server_proc.terminate()
        server_proc.join()
