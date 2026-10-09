import os
import shutil
import zipfile
from fastapi import UploadFile
from app.config import settings

def save_uploaded_file(upload_file: UploadFile) -> str:
    """Save an uploaded file safely to the sandboxed upload directory."""
    filename = os.path.basename(upload_file.filename)
    dest_path = os.path.join(settings.UPLOAD_DIR, filename)

    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    if filename.endswith(".zip"):
        extract_dir = os.path.join(settings.UPLOAD_DIR, f"extracted_{filename.replace('.zip', '')}")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(dest_path, 'r') as zip_ref:
            # Protect against Zip Slip vulnerabilities
            for member in zip_ref.namelist():
                filename_clean = os.path.basename(member)
                if not filename_clean or member.startswith("..") or member.startswith("/"):
                    continue
                zip_ref.extract(member, extract_dir)
        return extract_dir

    return dest_path
