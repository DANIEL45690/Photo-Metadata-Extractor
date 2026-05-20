# 📸 Photo Metadata Extractor v5.0

> **Professional Metadata Extraction & OSINT Intelligence Tool**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.0-red.svg)]()

<img width="1917" height="1080" alt="image_2026-05-20_23-24-06" src="https://github.com/user-attachments/assets/aa5eff02-9ebf-4fd8-b4a2-d56c24d3b21a" />

## 🚀 Overview

**Photo Metadata Extractor v5.0** is a powerful, all-in-one forensic and OSINT tool designed to extract, analyze, and visualize metadata from files across your system. Whether you're a cybersecurity professional, digital forensics investigator, or privacy enthusiast, this tool provides comprehensive insights hidden within digital files.

## ✨ Key Features

### 📷 Image Analysis
- **GPS Extraction** – Extract precise geolocation data from photos
- **EXIF Metadata** – Camera make, model, lens, ISO, aperture, shutter speed
- **Face Detection** – Detect and count faces using OpenCV
- **Steganography Detection** – Identify LSB-embedded hidden data
- **OCR Text Extraction** – Read text from images using Tesseract

### 📄 Document Processing
- **PDF Metadata** – Author, creator, page count, full text extraction
- **DOCX Analysis** – Core properties, word count, full content
- **Text Files** – Character count, word frequency

### 🎵 Audio & Video
- **Audio Metadata** – Duration, bitrate, sample rate, artist, album (MP3/WAV)
- **Video Analysis** – Resolution, FPS, codec, frame count, duration

### 📦 Archive Inspection
- **ZIP/TAR Analysis** – File lists, compression ratios, internal structure

### 🌍 OSINT Capabilities
- **IP Geolocation** – Multiple API sources (ip-api, ipinfo, ipwhois)
- **GPS Map Generation** – Interactive heatmaps with MarkerCluster
- **Reverse Geocoding** – Convert coordinates to addresses (OSM Nominatim)

### 💾 Data Management
- **SQLite Database** – Persistent storage of all scan results
- **JSON Export** – Complete structured exports for further analysis
- **Scan History** – Track all previous scans with detailed reports

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Database Schema](#database-schema)
- [Output Examples](#output-examples)
- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

## 🔧 Installation

### Prerequisites

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y tesseract-ocr libtesseract-dev
sudo apt-get install -y python3-opencv

# Install system dependencies (macOS)
brew install tesseract
brew install opencv

# Install system dependencies (Windows)
# Download and install Tesseract from: https://github.com/UB-Mannheim/tesseract/wiki
