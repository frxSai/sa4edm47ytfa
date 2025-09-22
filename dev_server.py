#!/usr/bin/env python3
"""
Local development server for the FastAPI Secret App
Run this file to start the development server locally
"""

import uvicorn
from main import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
