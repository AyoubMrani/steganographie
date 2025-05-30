import tkinter as tk
from tkinter import filedialog, ttk, messagebox, Scale
from PIL import Image, ImageTk
import os
import random
from numpy import asarray
import threading
import io
import zipfile
import shutil
import tempfile
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk

import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Génère une clé AES 256 bits à partir d'un mot de passe et d'un sel"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    """Chiffre les données avec AES-256"""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return salt + iv + ciphertext  # Salt + IV + Data

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Déchiffre les données avec AES-256"""
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Steganography App ")
        self.root.geometry("850x700")  # Increased height for additional controls
        self.root.configure(bg="#9fdbee")
        
        # Try to set app icon
        try:
            self.root.iconbitmap("lock.ico")  # You can add your own icon file
        except:
            pass
            
        # Variables
        self.icon_previous = ImageTk.PhotoImage(Image.open("icons/icon_prediction.png").resize((28, 28)))
        self.icon_upload = ImageTk.PhotoImage(Image.open("icons/upload.png").resize((28, 28)))
        self.icon_add= ImageTk.PhotoImage(Image.open("icons/ajouter1.png").resize((28, 28)))
        self.icon_remove= ImageTk.PhotoImage(Image.open("icons/bouton-supprimer.png").resize((28, 28)))
        self.icon_clear= ImageTk.PhotoImage(Image.open("icons/nettoyer.png").resize((28, 28)))
        self.icon_hide= ImageTk.PhotoImage(Image.open("icons/crypte1.png").resize((28, 28)))
        self.icon_hide1= ImageTk.PhotoImage(Image.open("icons/hide.png").resize((20, 20)))
        self.icon_extract= ImageTk.PhotoImage(Image.open("icons/decrypter.png").resize((20, 20)))
        self.icon_extract1= ImageTk.PhotoImage(Image.open("icons/debloque.png").resize((28, 28)))
        self.image_path = tk.StringVar()
        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.status = tk.StringVar()
        self.status.set("Ready")
        self.is_hiding_image = tk.BooleanVar(value=False)
        self.image_quality = tk.IntVar(value=60)  # Default image quality
        self.resize_percentage = tk.IntVar(value=100)  # Default no resize
        self.optimize_image = tk.BooleanVar(value=True)  # Default optimize
        self.use_multiple_files = tk.BooleanVar(value=False)  # Default single file
        self.max_file_size_mb = tk.DoubleVar(value=5.0)  # Default 5MB limit
        self.image_capacity_bytes = 0  # Store the capacity of the selected image
        self.hide_output_dir = tk.StringVar()
        self.hide_output_dir.set(os.path.expanduser("~"))  # Default to user's home directory
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.hide_tab = tk.Frame(self.notebook, bg="#9fdbee")
        self.extract_tab = tk.Frame(self.notebook, bg="#9fdbee")
        
        self.notebook.add(self.hide_tab, text="Hide File(s)",image=self.icon_hide1, compound="left" )
        self.notebook.add(self.extract_tab, text="Extract File(s)",image=self.icon_extract, compound="left")
         
        # Setup Hide Tab
        self.setup_hide_tab()
        
        # Setup Extract Tab
        self.setup_extract_tab()
        
        # Store original and compressed image data
        self.original_image = None
        self.compressed_image = None
        self.original_size = 0
        self.compressed_size = 0
        
        # Store multiple files
        self.selected_files = []
        self.total_files_size = 0
        self.temp_dir = tempfile.mkdtemp()  # Create a temporary directory
    
    def setup_hide_tab(self):
        """Setup the hide file tab"""
        # Create main frame with scrollbar
        main_container = tk.Frame(self.hide_tab, bg="#9fdbee")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        canvas = tk.Canvas(main_container, bg="#9fdbee")
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#9fdbee")
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Main frame
        main_frame = tk.Frame(scrollable_frame, bg="#9fdbee", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text="  Hide File(s) in Image",  image=self.icon_hide, compound="left",
                              font=("Helvetica", 16, "bold"), bg="#9fdbee")
        title_label.pack(pady=(0, 20))
        
        # Create content frame
        content_frame = tk.Frame(main_frame, bg="#9fdbee")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left frame for image
        left_frame = tk.LabelFrame(content_frame, text="Carrier Image",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Image preview
        self.image_preview = tk.Label(left_frame, text="No image selected", 
                                     bg="#ffffff", width=40, height=10)
        self.image_preview.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Image selection button
        select_image_btn = tk.Button(left_frame, text="Select Image", image=self.icon_previous, compound="left", 
                                    command=self.select_image,
                                    bg="#4f46e5", fg="white", padx=10, pady=5)
        select_image_btn.pack(pady=5)
        
        # Image path display
        self.image_path_label = tk.Label(left_frame, textvariable=self.image_path, 
                                        bg="#9fdbee", wraplength=300)
        self.image_path_label.pack(pady=5, fill=tk.X)
        
        # Image capacity info
        self.image_capacity_label = tk.Label(left_frame, text="Capacity: Unknown", font=("Segoe UI", 8, "bold"),
                                           bg="#9fdbee")
        self.image_capacity_label.pack(pady=5)
        
        # Right frame for file(s)
        right_frame = tk.LabelFrame(content_frame, text="File(s) to Hide", font=("Segoe UI", 8, "bold") ,bg="#9fdbee", padx=10, pady=10 )
        right_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        # File mode selection
        file_mode_frame = tk.Frame(right_frame, bg="#9fdbee")
        file_mode_frame.pack(fill=tk.X, pady=5)
        
        single_file_radio = tk.Radiobutton(file_mode_frame, text="Single File", 
                                          variable=self.use_multiple_files, value=False,
                                          bg="#9fdbee", command=self.toggle_file_mode)
        single_file_radio.pack(side=tk.LEFT, padx=10)
        
        multiple_files_radio = tk.Radiobutton(file_mode_frame, text="Multiple Files (ZIP)", 
                                             variable=self.use_multiple_files, value=True,
                                             bg="#9fdbee", command=self.toggle_file_mode)
        multiple_files_radio.pack(side=tk.LEFT, padx=10)
        
        # Single file frame
        self.single_file_frame = tk.Frame(right_frame, bg="#9fdbee")
        self.single_file_frame.pack(fill=tk.BOTH, expand=True)
        
        # File info
        self.file_info = tk.Label(self.single_file_frame, text="No file selected", 
                                 bg="#ffffff", width=40, height=10)
        self.file_info.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # File selection button
        select_file_btn = tk.Button(self.single_file_frame, text="Select File", image=self.icon_previous, compound="left",
                                   command=self.select_file,
                                   bg="#4f46e5", fg="white", padx=10, pady=5)
        select_file_btn.pack(pady=5)
        
        # File path display
        self.file_path_label = tk.Label(self.single_file_frame, textvariable=self.file_path, 
                                       bg="#9fdbee", wraplength=300)
        self.file_path_label.pack(pady=5, fill=tk.X)
        
        # Size limit info for single file
        self.single_file_capacity_frame = tk.Frame(self.single_file_frame, bg="#9fdbee")
        self.single_file_capacity_frame.pack(fill=tk.X, pady=5)
        
        self.single_file_capacity_label = tk.Label(self.single_file_capacity_frame, 
                                                 text="Max Size: Unknown", 
                                                 bg="#9fdbee", fg="#2563eb", 
                                                 font=("Helvetica", 9, "bold"))
        self.single_file_capacity_label.pack(side=tk.LEFT, padx=5)
        
        # Capacity usage for single file
        self.single_file_usage_frame = tk.Frame(self.single_file_frame, bg="#9fdbee")
        self.single_file_usage_frame.pack(fill=tk.X, pady=5)
        
        self.single_file_usage_label = tk.Label(self.single_file_usage_frame, 
                                              text="Capacity Usage:",font=("Segoe UI", 8, "bold"), bg="#9fdbee")
        self.single_file_usage_label.pack(side=tk.LEFT, padx=5)
        
        self.single_file_usage_bar = ttk.Progressbar(self.single_file_usage_frame, 
                                                   orient=tk.HORIZONTAL, length=200)
        self.single_file_usage_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.single_file_usage_percent = tk.Label(self.single_file_usage_frame, 
                                                text="0%", bg="#9fdbee", width=5)
        self.single_file_usage_percent.pack(side=tk.LEFT, padx=5)
        
        # Multiple files frame
        self.multiple_files_frame = tk.Frame(right_frame, bg="#9fdbee")
        # Initially hidden, will be shown when multiple files mode is selected
        
        # Size limit info frame
        size_limit_frame = tk.Frame(self.multiple_files_frame, bg="#9fdbee")
        size_limit_frame.pack(fill=tk.X, pady=5)
        
        # Size limit label (now just displays the limit, not editable)
        size_limit_label = tk.Label(size_limit_frame, text="Max Size:", bg="#9fdbee")
        size_limit_label.pack(side=tk.LEFT, padx=5)
        
        self.size_limit_display = tk.Label(size_limit_frame, 
                                          text="Based on image capacity", 
                                          bg="#9fdbee", fg="#2563eb", font=("Helvetica", 9, "bold"))
        self.size_limit_display.pack(side=tk.LEFT, padx=5)
        
        # Files list frame
        files_list_frame = tk.Frame(self.multiple_files_frame, bg="#9fdbee")
        files_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a frame for the listbox and scrollbar
        list_container = tk.Frame(files_list_frame, bg="#9fdbee")
        list_container.pack(fill=tk.BOTH, expand=True)
        
        # Files listbox with scrollbar
        self.files_listbox = tk.Listbox(list_container, height=8, width=40)
        files_scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.files_listbox.yview)
        self.files_listbox.config(yscrollcommand=files_scrollbar.set)
        
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Total size label
        self.total_size_label = tk.Label(files_list_frame, text="Total Size: 0 KB", bg="#9fdbee")
        self.total_size_label.pack(pady=5, anchor=tk.W)
        
        # Capacity usage indicator
        self.capacity_usage_frame = tk.Frame(files_list_frame, bg="#9fdbee")
        self.capacity_usage_frame.pack(fill=tk.X, pady=5)
        
        self.capacity_usage_label = tk.Label(self.capacity_usage_frame, text="Capacity Usage:",font=("Segoe UI", 8, "bold"), bg="#9fdbee")
        self.capacity_usage_label.pack(side=tk.LEFT, padx=5)
        
        self.capacity_usage_bar = ttk.Progressbar(self.capacity_usage_frame, orient=tk.HORIZONTAL, length=200)
        self.capacity_usage_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.capacity_usage_percent = tk.Label(self.capacity_usage_frame, text="0%", bg="#9fdbee", width=5)
        self.capacity_usage_percent.pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        files_buttons_frame = tk.Frame(self.multiple_files_frame, bg="#9fdbee")
        files_buttons_frame.pack(fill=tk.X, pady=5)
        
        # Add files button
        add_files_btn = tk.Button(files_buttons_frame, text="Add Files", image=self.icon_add, compound="left", 
                                 command=self.add_files,
                                 bg="#4f46e5", fg="white", padx=10, pady=5)
        add_files_btn.pack(side=tk.LEFT, padx=5)
        
        # Remove selected button
        remove_file_btn = tk.Button(files_buttons_frame, text="Remove Selected", image=self.icon_remove, compound="left",
                                   command=self.remove_selected_file,
                                   bg="#ef4444", fg="white", padx=10, pady=5)
        remove_file_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear all button
        clear_files_btn = tk.Button(files_buttons_frame, text="Clear All", image=self.icon_clear, compound="left",
                                   command=self.clear_files,
                                   bg="#6b7280", fg="white", padx=10, pady=5)
        clear_files_btn.pack(side=tk.LEFT, padx=5)
        
        # Set equal weight to columns
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Image options frame (initially hidden)
        self.image_options_frame = tk.LabelFrame(main_frame, text="Image Compression Options", bg="#9fdbee", padx=10, pady=10)
        
        # Image quality slider
        quality_label = tk.Label(self.image_options_frame, text="Image Quality:", bg="#9fdbee")
        quality_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.quality_slider = Scale(self.image_options_frame, from_=10, to=100, 
                                   orient=tk.HORIZONTAL, variable=self.image_quality,
                                   length=300, bg="#9fdbee", highlightthickness=0,
                                   command=self.update_compression_preview)
        self.quality_slider.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        quality_value_label = tk.Label(self.image_options_frame, textvariable=self.image_quality, 
                                      bg="#9fdbee", width=3)
        quality_value_label.grid(row=0, column=2, padx=5, pady=5)
        
        # Resize slider
        resize_label = tk.Label(self.image_options_frame, text="Resize %:", bg="#9fdbee")
        resize_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.resize_slider = Scale(self.image_options_frame, from_=10, to=100, 
                                  orient=tk.HORIZONTAL, variable=self.resize_percentage,
                                  length=300, bg="#9fdbee", highlightthickness=0,
                                  command=self.update_compression_preview)
        self.resize_slider.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        resize_value_label = tk.Label(self.image_options_frame, textvariable=self.resize_percentage, 
                                     bg="#9fdbee", width=3)
        resize_value_label.grid(row=1, column=2, padx=5, pady=5)
        
        # Optimize checkbox
        optimize_check = tk.Checkbutton(self.image_options_frame, text="Optimize Image", 
                                       variable=self.optimize_image, bg="#9fdbee",
                                       command=self.update_compression_preview)
        optimize_check.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        
        # Preview frame
        preview_frame = tk.Frame(self.image_options_frame, bg="#9fdbee")
        preview_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=10, sticky="ew")
        
        # Original image preview
        original_preview_frame = tk.LabelFrame(preview_frame, text="Original", bg="#9fdbee", padx=5, pady=5)
        original_preview_frame.grid(row=0, column=0, padx=5, pady=5)
        
        self.original_preview = tk.Label(original_preview_frame, text="No image", bg="#ffffff", width=20, height=10)
        self.original_preview.pack(padx=5, pady=5)
        
        self.original_size_label = tk.Label(original_preview_frame, text="Size: 0 KB", bg="#9fdbee")
        self.original_size_label.pack(pady=5)
        
        # Compressed image preview
        compressed_preview_frame = tk.LabelFrame(preview_frame, text="Compressed", bg="#9fdbee", padx=5, pady=5)
        compressed_preview_frame.grid(row=0, column=1, padx=5, pady=5)
        
        self.compressed_preview = tk.Label(compressed_preview_frame, text="No image", bg="#ffffff", width=20, height=10)
        self.compressed_preview.pack(padx=5, pady=5)
        
        self.compressed_size_label = tk.Label(compressed_preview_frame, text="Size: 0 KB", bg="#9fdbee")
        self.compressed_size_label.pack(pady=5)
        
        # Apply compression button
        self.apply_compression_btn = tk.Button(self.image_options_frame, text="Apply Compression", 
                                             command=self.apply_compression,
                                             bg="#4f46e5", fg="white", padx=10, pady=5,
                                             state=tk.DISABLED)
        self.apply_compression_btn.grid(row=4, column=0, columnspan=3, padx=5, pady=10)
        
        self.image_options_frame.grid_columnconfigure(1, weight=1)
        
        # Output directory frame
        output_frame = tk.LabelFrame(main_frame, text="Output Directory",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        output_frame.pack(fill=tk.X, pady=10)
        
        # Output directory path
        output_dir_entry = tk.Entry(output_frame, textvariable=self.hide_output_dir, width=60)
        output_dir_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        browse_btn = tk.Button(output_frame, text="Browse", image=self.icon_upload, compound="left",
                              command=self.select_hide_output_dir,
                              bg="#4f46e5", fg="white")
        browse_btn.grid(row=0, column=1, padx=5, pady=5)
        
        output_frame.grid_columnconfigure(0, weight=1)
        
        # Password frame
        self.password_frame = tk.LabelFrame(main_frame, text="Security",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        self.password_frame.pack(fill=tk.X, pady=10)
        
        # Password label and entry
        password_label = tk.Label(self.password_frame, text="Password:", bg="#9fdbee")
        password_label.grid(row=0, column=0, padx=5, pady=5)
        
        password_entry = tk.Entry(self.password_frame, textvariable=self.password, show="*", width=40)
        password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg="#9fdbee")
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Hide file button
        self.hide_btn = tk.Button(buttons_frame, text="Hide File(s) in Image", image=self.icon_hide, compound="left",
                                 command=self.hide_file,
                                 bg="#4f46e5", fg="white", padx=20, pady=10,
                                 state=tk.DISABLED)
        self.hide_btn.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Status bar
        status_frame = tk.Frame(main_frame, bg="#9fdbee")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.progress_bar = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, 
                                           length=100, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        status_label = tk.Label(status_frame, textvariable=self.status, bg="#9fdbee")
        status_label.pack(pady=5)
        
        # Check for valid inputs when variables change
        self.image_path.trace_add("write", self.check_inputs)
        self.file_path.trace_add("write", self.check_inputs)
        self.password.trace_add("write", self.check_inputs)
        self.use_multiple_files.trace_add("write", self.check_inputs)
        self.hide_output_dir.trace_add("write", self.check_inputs)
    
    def setup_extract_tab(self):
        """Setup the extract file tab"""
        # Create main frame
        main_frame = tk.Frame(self.extract_tab, bg="#9fdbee", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text=" Extract Hidden File(s)",image=self.icon_extract1, compound="left",
                              font=("Helvetica", 16, "bold"), bg="#9fdbee")
        title_label.pack(pady=(0, 20))
        
        # Image frame
        image_frame = tk.LabelFrame(main_frame, text="Image with Hidden Data",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        image_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Image preview
        self.extract_image_preview = tk.Label(image_frame, text="No image selected", 
                                            bg="#ffffff", height=10)
        self.extract_image_preview.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Image selection button
        select_extract_image_btn = tk.Button(image_frame, text="Select Image", image=self.icon_previous, compound="left", 
                                           command=self.select_extract_image,
                                           bg="#4f46e5", fg="white", padx=10, pady=5)
        select_extract_image_btn.pack(pady=5)
        
        # Image path display
        self.extract_image_path = tk.StringVar()
        self.extract_image_path_label = tk.Label(image_frame, textvariable=self.extract_image_path, 
                                               bg="#9fdbee", wraplength=700)
        self.extract_image_path_label.pack(pady=5, fill=tk.X)
        
        # Password frame
        extract_password_frame = tk.LabelFrame(main_frame, text="Security",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        extract_password_frame.pack(fill=tk.X, pady=10)
        
        # Password label and entry
        extract_password_label = tk.Label(extract_password_frame, text="Password:", bg="#9fdbee")
        extract_password_label.grid(row=0, column=0, padx=5, pady=5)
        
        self.extract_password = tk.StringVar()
        extract_password_entry = tk.Entry(extract_password_frame, textvariable=self.extract_password, 
                                        show="*", width=40)
        extract_password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Output directory frame
        output_frame = tk.LabelFrame(main_frame, text="Output Directory",font=("Segoe UI", 8, "bold"), bg="#9fdbee", padx=10, pady=10)
        output_frame.pack(fill=tk.X, pady=10)
        
        # Output directory path
        self.output_dir = tk.StringVar()
        self.output_dir.set(os.path.expanduser("~"))  # Default to user's home directory
        
        output_dir_entry = tk.Entry(output_frame, textvariable=self.output_dir, width=60)
        output_dir_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        browse_btn = tk.Button(output_frame, text="Browse", image=self.icon_upload, compound="left",
                              command=self.select_output_dir,
                              bg="#4f46e5", fg="white")
        browse_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # Auto extract ZIP option
        self.auto_extract_zip = tk.BooleanVar(value=True)
        auto_extract_check = tk.Checkbutton(output_frame, text="Auto-extract ZIP files", 
                                           variable=self.auto_extract_zip, bg="#9fdbee")
        auto_extract_check.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        
        output_frame.grid_columnconfigure(0, weight=1)
        
        # Buttons frame
        extract_buttons_frame = tk.Frame(main_frame, bg="#9fdbee")
        extract_buttons_frame.pack(fill=tk.X, pady=10)
        
        # Extract file button
        self.extract_btn = tk.Button(extract_buttons_frame, text="Extract Hidden File(s)", 
                                    command=self.extract_file,
                                    bg="#4f46e5", fg="white", padx=20, pady=10,
                                    state=tk.DISABLED)
        self.extract_btn.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Status bar
        extract_status_frame = tk.Frame(main_frame, bg="#9fdbee")
        extract_status_frame.pack(fill=tk.X, pady=10)
        
        self.extract_progress_bar = ttk.Progressbar(extract_status_frame, orient=tk.HORIZONTAL, 
                                                  length=100, mode='indeterminate')
        self.extract_progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        self.extract_status = tk.StringVar()
        self.extract_status.set("Ready")
        extract_status_label = tk.Label(extract_status_frame, textvariable=self.extract_status, bg="#eaff72")
        extract_status_label.pack(pady=5)
        
        # Check for valid inputs when variables change
        self.extract_image_path.trace_add("write", self.check_extract_inputs)
        self.extract_password.trace_add("write", self.check_extract_inputs)
        self.output_dir.trace_add("write", self.check_extract_inputs)
    
    def select_hide_output_dir(self):
        """Open directory dialog to select output directory for hiding"""
        dir_path = filedialog.askdirectory(
            title="Select Output Directory for Hidden File"
        )
        
        if dir_path:
            self.hide_output_dir.set(dir_path)
    
    def toggle_file_mode(self):
        """Toggle between single file and multiple files mode"""
        if self.use_multiple_files.get():
            # Switch to multiple files mode
            self.single_file_frame.pack_forget()
            self.multiple_files_frame.pack(fill=tk.BOTH, expand=True)
            self.file_path.set("")  # Clear single file path
        else:
            # Switch to single file mode
            self.multiple_files_frame.pack_forget()
            self.single_file_frame.pack(fill=tk.BOTH, expand=True)
            # Clear multiple files list
            self.clear_files()
    
    def add_files(self):
        """Open file dialog to select multiple files"""
        file_paths = filedialog.askopenfilenames(
            title="Select Files to Hide"
        )
        
        if not file_paths:
            return
            
        # Get max size in bytes (based on image capacity)
        max_size_bytes = self.image_capacity_bytes
        
        if max_size_bytes <= 0:
            messagebox.showwarning(
                "No Image Selected", 
                "Please select a carrier image first to determine the maximum file size."
            )
            return
        
        # Add files to the list
        for file_path in file_paths:
            file_size = os.path.getsize(file_path)
            
            # Check if adding this file would exceed the limit
            if self.total_files_size + file_size > max_size_bytes:
                messagebox.showwarning(
                    "Size Limit Exceeded", 
                    f"Adding '{os.path.basename(file_path)}' would exceed the image capacity.\n"
                    f"Current total: {self.total_files_size / (1024 * 1024):.2f} MB\n"
                    f"File size: {file_size / (1024 * 1024):.2f} MB\n"
                    f"Remaining capacity: {(max_size_bytes - self.total_files_size) / (1024 * 1024):.2f} MB"
                )
                continue
                
            # Add file to the list
            file_name = os.path.basename(file_path)
            file_size_kb = file_size / 1024
            list_item = f"{file_name} ({file_size_kb:.2f} KB)"
            
            # Check if file is already in the list
            if file_path not in [f[0] for f in self.selected_files]:
                self.files_listbox.insert(tk.END, list_item)
                self.selected_files.append((file_path, file_size))
                self.total_files_size += file_size
                
        # Update total size display and capacity usage
        self.update_total_size_display()
        self.update_capacity_usage()
        
        # Check inputs to enable/disable hide button
        self.check_inputs()
    
    def remove_selected_file(self):
        """Remove the selected file from the list"""
        selected_indices = self.files_listbox.curselection()
        
        if not selected_indices:
            return
            
        # Remove files in reverse order to avoid index issues
        for index in sorted(selected_indices, reverse=True):
            file_path, file_size = self.selected_files[index]
            self.total_files_size -= file_size
            del self.selected_files[index]
            self.files_listbox.delete(index)
            
        # Update total size display and capacity usage
        self.update_total_size_display()
        self.update_capacity_usage()
        
        # Check inputs to enable/disable hide button
        self.check_inputs()
    
    def clear_files(self):
        """Clear all files from the list"""
        self.files_listbox.delete(0, tk.END)
        self.selected_files = []
        self.total_files_size = 0
        
        # Update total size display and capacity usage
        self.update_total_size_display()
        self.update_capacity_usage()
        
        # Check inputs to enable/disable hide button
        self.check_inputs()
    
    def update_total_size_display(self):
        """Update the total size display"""
        if self.total_files_size < 1024 * 1024:  # Less than 1MB
            size_text = f"Total Size: {self.total_files_size / 1024:.2f} KB"
        else:
            size_text = f"Total Size: {self.total_files_size / (1024 * 1024):.2f} MB"
            
        self.total_size_label.config(text=size_text)
    
    def update_capacity_usage(self):
        """Update the capacity usage bar and percentage"""
        if self.image_capacity_bytes <= 0:
            # No image selected or invalid capacity
            self.capacity_usage_bar["value"] = 0
            self.capacity_usage_percent.config(text="0%")
            return
            
        # Calculate percentage
        usage_percent = (self.total_files_size / self.image_capacity_bytes) * 100
        
        # Update progress bar
        self.capacity_usage_bar["value"] = min(usage_percent, 100)
        
        # Update percentage text
        self.capacity_usage_percent.config(text=f"{min(usage_percent, 100):.1f}%")
        
        # Change color based on usage
        if usage_percent < 70:
            self.capacity_usage_percent.config(fg="#047857")  # Green
        elif usage_percent < 90:
            self.capacity_usage_percent.config(fg="#d97706")  # Orange
        else:
            self.capacity_usage_percent.config(fg="#dc2626")  # Red
    
    def update_single_file_capacity_usage(self, file_size=0):
        """Update the capacity usage for single file mode"""
        if self.image_capacity_bytes <= 0:
            # No image selected or invalid capacity
            self.single_file_usage_bar["value"] = 0
            self.single_file_usage_percent.config(text="0%")
            return
            
        # Calculate percentage
        usage_percent = (file_size / self.image_capacity_bytes) * 100
        
        # Update progress bar
        self.single_file_usage_bar["value"] = min(usage_percent, 100)
        
        # Update percentage text
        self.single_file_usage_percent.config(text=f"{min(usage_percent, 100):.1f}%")
        
        # Change color based on usage
        if usage_percent < 70:
            self.single_file_usage_percent.config(fg="#047857")  # Green
        elif usage_percent < 90:
            self.single_file_usage_percent.config(fg="#d97706")  # Orange
        else:
            self.single_file_usage_percent.config(fg="#dc2626")  # Red
    
    def select_image(self):
        """Open file dialog to select an image"""
        file_path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        
        if file_path:
            self.image_path.set(file_path)
            # Display image preview
            try:
                img = Image.open(file_path)
                img = img.resize((300, 200), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.image_preview.config(image=photo)
                self.image_preview.image = photo  # Keep a reference
                self.image_preview.config(text="")
                
                # Calculate and display image capacity
                self.calculate_image_capacity(file_path)
                
                # Update capacity usage if in multiple files mode
                if self.use_multiple_files.get():
                    self.update_capacity_usage()
                else:
                    # Update single file capacity display
                    if self.file_path.get():
                        file_size = os.path.getsize(self.file_path.get())
                        self.update_single_file_capacity_usage(file_size)
                
            except Exception as e:
                self.image_preview.config(text=f"Error loading image: {e}")
                self.image_preview.image = None
                self.image_capacity_bytes = 0
    
    def calculate_image_capacity(self, image_path):
        """Calculate and display the capacity of the image for hiding data"""
        try:
            img = Image.open(image_path)
            width, height = img.size
            
            # Calculate capacity (very rough estimate)
            # Each pixel can store 3 bits (1 in each RGB channel)
            # We reserve some space for headers
            total_pixels = width * height
            total_bits = total_pixels * 3
            total_bytes = total_bits // 8
            
            # Reserve some space for headers (extension, file size, etc.)
            usable_bytes = total_bytes - 1024  # Reserve 1KB for headers
            
            if usable_bytes < 0:
                usable_bytes = 0
                
            # Store the capacity in bytes
            self.image_capacity_bytes = usable_bytes
                
            # Display capacity
            if usable_bytes < 1024:  # Less than 1KB
                capacity_text = f"Capacity: {usable_bytes} bytes"
            elif usable_bytes < 1024 * 1024:  # Less than 1MB
                capacity_text = f"Capacity: {usable_bytes / 1024:.2f} KB"
            else:
                capacity_text = f"Capacity: {usable_bytes / (1024 * 1024):.2f} MB"
                
            self.image_capacity_label.config(text=capacity_text)
            
            # Update the size limit display in multiple files mode
            if usable_bytes < 1024 * 1024:  # Less than 1MB
                limit_text = f"{usable_bytes / 1024:.2f} KB"
            else:
                limit_text = f"{usable_bytes / (1024 * 1024):.2f} MB"
                
            self.size_limit_display.config(text=limit_text)
            
            # Update the size limit display in single file mode
            self.single_file_capacity_label.config(text=f"Max Size: {limit_text}")
            
        except Exception as e:
            self.image_capacity_label.config(text="Capacity: Unknown")
            self.image_capacity_bytes = 0
            self.size_limit_display.config(text="Unknown")
            self.single_file_capacity_label.config(text="Max Size: Unknown")
            print(f"Error calculating capacity: {e}")
    
    def select_extract_image(self):
        """Open file dialog to select an image for extraction"""
        file_path = filedialog.askopenfilename(
            title="Select Image with Hidden Data",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        
        if file_path:
            self.extract_image_path.set(file_path)
            # Display image preview
            try:
                img = Image.open(file_path)
                img = img.resize((400, 250), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.extract_image_preview.config(image=photo)
                self.extract_image_preview.image = photo  # Keep a reference
                self.extract_image_preview.config(text="")
            except Exception as e:
                self.extract_image_preview.config(text=f"Error loading image: {e}")
                self.extract_image_preview.image = None
    
    def select_output_dir(self):
        """Open directory dialog to select output directory"""
        dir_path = filedialog.askdirectory(
            title="Select Output Directory"
        )
        
        if dir_path:
            self.output_dir.set(dir_path)
    
    def select_file(self):
        """Open file dialog to select a file to hide"""
        file_path = filedialog.askopenfilename(
            title="Select File to Hide"
        )
        
        if file_path:
            # Check if the file size exceeds the image capacity
            file_size = os.path.getsize(file_path)
            
            if self.image_capacity_bytes > 0 and file_size > self.image_capacity_bytes:
                messagebox.showwarning(
                    "File Too Large", 
                    f"The selected file ({file_size / (1024 * 1024):.2f} MB) exceeds the image capacity ({self.image_capacity_bytes / (1024 * 1024):.2f} MB)."
                )
                return
                
            self.file_path.set(file_path)
            file_name = os.path.basename(file_path)
            file_size_kb = file_size / 1024
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Check if the selected file is an image
            is_image = file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']
            self.is_hiding_image.set(is_image)
            
            # Display file info
            if is_image:
                try:
                    # Show image preview
                    img = Image.open(file_path)
                    img = img.resize((300, 200), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.file_info.config(image=photo)
                    self.file_info.image = photo  # Keep a reference
                    self.file_info.config(text="")
                    
                    # Store original image for compression
                    self.original_image = Image.open(file_path)
                    self.original_size = file_size
                    
                    # Show image options
                    self.image_options_frame.pack(fill=tk.X, pady=10, before=self.password_frame)
                    
                    # Update compression preview
                    self.update_compression_preview()
                    
                    # Update status
                    self.status.set(f"Selected image to hide: {file_name} ({file_size_kb:.2f} KB)")
                except Exception as e:
                    self.file_info.config(text=f"Error loading image: {e}")
                    self.file_info.image = None
            else:
                # Hide image options if not an image
                self.image_options_frame.pack_forget()
                
                # Display regular file info
                self.file_info.config(
                    text=f"File: {file_name}\nSize: {file_size_kb:.2f} KB\nType: {file_ext}",
                    image=""
                )
            
            # Update capacity usage for single file
            self.update_single_file_capacity_usage(file_size)
    
    def update_compression_preview(self, *args):
        """Update the compression preview when settings change"""
        if not self.original_image:
            return
            
        # Enable the apply button
        self.apply_compression_btn.config(state=tk.NORMAL)
        
        # Get compression settings
        quality = self.image_quality.get()
        resize_percent = self.resize_percentage.get()
        optimize = self.optimize_image.get()
        
        # Create a thread to avoid UI freezing
        thread = threading.Thread(target=self.process_compression_preview, 
                                 args=(quality, resize_percent, optimize))
        thread.daemon = True
        thread.start()
    
    def process_compression_preview(self, quality, resize_percent, optimize):
        """Process the compression preview in a separate thread"""
        try:
            # Create a copy of the original image
            img = self.original_image.copy()
            
            # Resize if needed
            if resize_percent < 100:
                width, height = img.size
                new_width = int(width * resize_percent / 100)
                new_height = int(height * resize_percent / 100)
                img = img.resize((new_width, new_height), Image.LANCZOS)
            
            # Save to a bytes buffer to get compressed size
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=quality, optimize=optimize)
            compressed_data = buffer.getvalue()
            compressed_size = len(compressed_data)
            
            # Store the compressed image
            self.compressed_image = Image.open(io.BytesIO(compressed_data))
            self.compressed_size = compressed_size
            
            # Update UI on the main thread
            self.root.after(0, self.update_compression_ui, img, compressed_size)
            
        except Exception as e:
            self.root.after(0, lambda: self.status.set(f"Error in compression preview: {e}"))
    
    def update_compression_ui(self, img, compressed_size):
        """Update the UI with compression preview"""
        # Update original preview
        original_img = self.original_image.copy()
        original_img.thumbnail((150, 150))
        original_photo = ImageTk.PhotoImage(original_img)
        self.original_preview.config(image=original_photo)
        self.original_preview.image = original_photo
        self.original_size_label.config(text=f"Size: {self.original_size / 1024:.1f} KB")
        
        # Update compressed preview
        compressed_img = img.copy()
        compressed_img.thumbnail((150, 150))
        compressed_photo = ImageTk.PhotoImage(compressed_img)
        self.compressed_preview.config(image=compressed_photo)
        self.compressed_preview.image = compressed_photo
        self.compressed_size_label.config(text=f"Size: {compressed_size / 1024:.1f} KB")
        
        # Update status with compression ratio
        ratio = (1 - compressed_size / self.original_size) * 100
        self.status.set(f"Compression: {ratio:.1f}% reduction in size")
        
        # Update capacity usage for single file
        self.update_single_file_capacity_usage(compressed_size)
    
    def apply_compression(self):
        """Apply the compression to the image file"""
        if not self.compressed_image:
            return
            
        # Create a temporary file for the compressed image
        temp_dir = os.path.dirname(self.file_path.get())
        temp_file = os.path.join(temp_dir, "compressed_image_temp.jpg")
        
        # Save the compressed image
        self.compressed_image.save(temp_file, "JPEG", 
                                  quality=self.image_quality.get(),
                                  optimize=self.optimize_image.get())
        
        # Update the file path
        self.file_path.set(temp_file)
        
        # Update status
        self.status.set(f"Image compressed: {self.compressed_size / 1024:.1f} KB " +
                       f"({(1 - self.compressed_size / self.original_size) * 100:.1f}% reduction)")
        
        # Disable the apply button
        self.apply_compression_btn.config(state=tk.DISABLED)
        
        # Update capacity usage for single file
        self.update_single_file_capacity_usage(self.compressed_size)
    
    def check_inputs(self, *args):
        """Check if all required inputs are provided for hiding"""
        if self.image_path.get() and self.password.get() and os.path.exists(self.hide_output_dir.get()):
            if self.use_multiple_files.get():
                # Multiple files mode
                if len(self.selected_files) > 0:
                    self.hide_btn.config(state=tk.NORMAL)
                else:
                    self.hide_btn.config(state=tk.DISABLED)
            else:
                # Single file mode
                if self.file_path.get():
                    self.hide_btn.config(state=tk.NORMAL)
                else:
                    self.hide_btn.config(state=tk.DISABLED)
        else:
            self.hide_btn.config(state=tk.DISABLED)
    
    def check_extract_inputs(self, *args):
        """Check if all required inputs are provided for extraction"""
        if self.extract_image_path.get() and self.extract_password.get() and os.path.exists(self.output_dir.get()):
            self.extract_btn.config(state=tk.NORMAL)
        else:
            self.extract_btn.config(state=tk.DISABLED)
    
    def create_zip_file(self):
        """Create a ZIP file from the selected files"""
        # Create a temporary ZIP file
        zip_filename = os.path.join(self.temp_dir, "hidden_files.zip")
        
        try:
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path, _ in self.selected_files:
                    # Add file to the ZIP
                    zipf.write(file_path, os.path.basename(file_path))
                    
            return zip_filename
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create ZIP file: {e}")
            return None
    
    def hide_file(self):
        """Hide the selected file in the image"""
        # Validate inputs
        if not os.path.exists(self.image_path.get()):
            messagebox.showerror("Error", "Image file not found.")
            return
            
        if not self.password.get():
            messagebox.showerror("Error", "Password is required.")
            return
            
        if not os.path.exists(self.hide_output_dir.get()):
            messagebox.showerror("Error", "Output directory not found.")
            return
            
        # Check if we're using multiple files
        if self.use_multiple_files.get():
            if not self.selected_files:
                messagebox.showerror("Error", "No files selected.")
                return
                
            # Create a ZIP file from the selected files
            self.status.set("Creating ZIP archive...")
            zip_file = self.create_zip_file()
            
            if not zip_file:
                return
                
            # Use the ZIP file as the file to hide
            file_to_hide = zip_file
        else:
            # Single file mode
            if not os.path.exists(self.file_path.get()):
                messagebox.showerror("Error", "File to hide not found.")
                return
                
            file_to_hide = self.file_path.get()
        
        # Start processing in a separate thread
        self.progress_bar.start(10)
        self.status.set("Processing...")
        self.hide_btn.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self.process_steganography, args=(file_to_hide,))
        thread.daemon = True
        thread.start()
    
    def extract_file(self):
        """Extract hidden file from the image"""
        # Validate inputs
        if not os.path.exists(self.extract_image_path.get()):
            messagebox.showerror("Error", "Image file not found.")
            return
            
        if not self.extract_password.get():
            messagebox.showerror("Error", "Password is required.")
            return
            
        if not os.path.exists(self.output_dir.get()):
            messagebox.showerror("Error", "Output directory not found.")
            return
        
        # Start processing in a separate thread
        self.extract_progress_bar.start(10)
        self.extract_status.set("Extracting...")
        self.extract_btn.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self.process_extraction)
        thread.daemon = True
        thread.start()
    
    def process_steganography(self, file_to_hide):
        """Process the steganography operation in a separate thread"""
        try:
            # Generate output filename
            output_filename = "hidden_file.png"
            
            # If hiding a single file, use a more descriptive name
            if not self.use_multiple_files.get():
                original_filename = os.path.basename(self.file_path.get())
                base_name = os.path.splitext(original_filename)[0]
                output_filename = f"{base_name}_hidden.png"
            
            # Get output path
            output_path = os.path.join(self.hide_output_dir.get(), output_filename)
            
            # Call the steganography function
            self.hide_file_in_image(
                file_to_hide,
                self.image_path.get(),
                output_path,
                self.password.get()
            )
            
            # Update UI on the main thread
            self.root.after(0, self.on_process_complete, output_path)
            
        except Exception as e:
            # Handle errors on the main thread
            self.root.after(0, self.on_process_error, str(e))
    
    def process_extraction(self):
        """Process the extraction operation in a separate thread"""
        try:
            # Call the extraction function
            output_file = self.extract_file_from_image(
                self.extract_image_path.get(),
                self.output_dir.get(),
                self.extract_password.get()
            )
            
            # Check if it's a ZIP file and auto-extract if enabled
            if (self.auto_extract_zip.get() and 
                output_file.lower().endswith('.zip')):
                # Extract the ZIP file
                self.extract_status.set("Extracting ZIP archive...")
                extract_dir = os.path.join(
                    self.output_dir.get(), 
                    f"extracted_files_{int(time.time())}"
                )
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(output_file, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Update output file to the extraction directory
                output_file = extract_dir
            
            # Update UI on the main thread
            self.root.after(0, self.on_extraction_complete, output_file)
            
        except Exception as e:
            # Handle errors on the main thread
            self.root.after(0, self.on_extraction_error, str(e))
    
    def on_process_complete(self, output_path):
        """Called when processing is complete"""
        self.progress_bar.stop()
        self.status.set(f"File hidden successfully! Saved to: {output_path}")
        self.hide_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Success", f"File hidden successfully!\nSaved to: {output_path}")
        
        # Clean up temporary files
        self.cleanup_temp_files()
    
    def on_process_error(self, error_msg):
        """Called when an error occurs during processing"""
        self.progress_bar.stop()
        self.status.set(f"Error: {error_msg}")
        self.hide_btn.config(state=tk.NORMAL)
        messagebox.showerror("Error", f"An error occurred: {error_msg}")
        
        # Clean up temporary files
        self.cleanup_temp_files()
    
    def cleanup_temp_files(self):
        """Clean up any temporary files created during processing"""
        try:
            # Check if we're using a temporary compressed file
            file_path = self.file_path.get()
            if file_path and "compressed_image_temp.jpg" in file_path and os.path.exists(file_path):
                os.remove(file_path)
            
            # Clean up ZIP file if it exists
            zip_file = os.path.join(self.temp_dir, "hidden_files.zip")
            if os.path.exists(zip_file):
                os.remove(zip_file)
                
        except Exception as e:
            print(f"Error cleaning up temporary files: {e}")
    
    def on_extraction_complete(self, output_file):
        """Called when extraction is complete"""
        self.extract_progress_bar.stop()
        
        # Check if output_file is a directory (extracted ZIP)
        if os.path.isdir(output_file):
            self.extract_status.set(f"Files extracted successfully to: {output_file}")
            messagebox.showinfo("Success", f"ZIP archive extracted successfully!\nFiles saved to: {output_file}")
        else:
            self.extract_status.set(f"File extracted successfully! Saved as: {output_file}")
            
            # Check if extracted file is an image and offer to view it
            file_ext = os.path.splitext(output_file)[1].lower()
            if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
                result = messagebox.askyesno("Success", 
                    f"Image extracted successfully!\nSaved as: {output_file}\n\nWould you like to view the extracted image?")
                if result:
                    self.view_extracted_image(output_file)
            else:
                messagebox.showinfo("Success", f"File extracted successfully!\nSaved as: {output_file}")
        
        self.extract_btn.config(state=tk.NORMAL)
    
    def view_extracted_image(self, image_path):
        """Open a new window to view the extracted image"""
        view_window = tk.Toplevel(self.root)
        view_window.title("Extracted Image")
        view_window.geometry("800x600")
        
        # Create a frame for the image
        frame = tk.Frame(view_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Load and display the image
        try:
            img = Image.open(image_path)
            
            # Calculate appropriate size while maintaining aspect ratio
            width, height = img.size
            max_width = 750
            max_height = 500
            
            if width > max_width or height > max_height:
                ratio = min(max_width / width, max_height / height)
                width = int(width * ratio)
                height = int(height * ratio)
                img = img.resize((width, height), Image.LANCZOS)
            
            photo = ImageTk.PhotoImage(img)
            
            # Create canvas to display image
            canvas = tk.Canvas(frame, width=width, height=height)
            canvas.pack(fill=tk.BOTH, expand=True)
            canvas.create_image(width//2, height//2, image=photo)
            canvas.image = photo  # Keep a reference
            
            # Add image info
            info_text = f"Image: {os.path.basename(image_path)}\nDimensions: {img.width} x {img.height} pixels"
            info_label = tk.Label(frame, text=info_text, justify=tk.LEFT, pady=10)
            info_label.pack()
            
        except Exception as e:
            error_label = tk.Label(frame, text=f"Error loading image: {e}")
            error_label.pack(pady=20)
    
    def on_extraction_error(self, error_msg):
        """Called when an error occurs during extraction"""
        self.extract_progress_bar.stop()
        self.extract_status.set(f"Error: {error_msg}")
        self.extract_btn.config(state=tk.NORMAL)
        messagebox.showerror("Error", f"An error occurred: {error_msg}")
    
    def file_to_bits(self, filepath):
        """Convert file to bits"""
        with open(filepath, "rb") as f:
            content = f.read()
        return ''.join([bin(byte)[2:].zfill(8) for byte in content]), len(content)
    
    def bits_to_bytes(self, bits):
        """Convert bits to bytes"""
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    
    def compress_image(self, input_path, output_path=None, quality=60, resize_percent=100, optimize=True):
        """Compress an image file"""
        if not output_path:
            # Use the same directory as input if no output path specified
            dir_name = os.path.dirname(input_path)
            file_name = os.path.basename(input_path)
            output_path = os.path.join(dir_name, f"compressed_{file_name}")
        
        # Open the image
        image = Image.open(input_path)
        
        # Resize if needed
        if resize_percent < 100:
            width, height = image.size
            new_width = int(width * resize_percent / 100)
            new_height = int(height * resize_percent / 100)
            image = image.resize((new_width, new_height), Image.LANCZOS)
        
        # Save with compression
        image.save(output_path, quality=quality, optimize=optimize)
        
        return output_path
    
    def preprocess_image_file(self, image_path):
        """Preprocess image file before hiding (resize/compress if needed)"""
        # Only process if it's an image file
        file_ext = os.path.splitext(image_path)[1].lower()
        if file_ext not in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            return image_path
            
        # Get compression settings
        quality = self.image_quality.get()
        resize_percent = self.resize_percentage.get()
        optimize = self.optimize_image.get()
        
        # Create a temporary file
        temp_dir = os.path.dirname(image_path)
        temp_file = os.path.join(temp_dir, "temp_processed_image.jpg")
        
        try:
            # Compress the image
            self.compress_image(
                image_path, 
                temp_file, 
                quality=quality,
                resize_percent=resize_percent,
                optimize=optimize
            )
            
            # Return the path to the processed image
            return temp_file
        except Exception as e:
            print(f"Error preprocessing image: {e}")
            # If there's an error, return the original path
            return image_path
    
    def hide_file_in_image(self, file_path, image_path, output_path, password="mysecret"):
        """Hide a file in an image using LSB steganography"""
        # Check if we're hiding an image and preprocess if needed
        if not self.use_multiple_files.get() and self.is_hiding_image.get():
            processed_file_path = self.preprocess_image_file(file_path)
            if processed_file_path != file_path:
                file_path = processed_file_path
                # Update status
                self.root.after(0, lambda: self.status.set("Preprocessed image for hiding..."))
        
        # Load image
        image = Image.open(image_path)
        data = asarray(image).copy()

        # Flatten image
        flat_pixels = data.reshape(-1, 3).reshape(-1)

        # Read file and convert to bits
        with open(file_path, "rb") as f:
            original_data = f.read()

        encrypted_data = encrypt_data(original_data, password)
        file_bits = ''.join([bin(byte)[2:].zfill(8) for byte in encrypted_data])
        file_bytes_length = len(encrypted_data)
        file_extension = os.path.splitext(file_path)[1][1:]  # e.g., 'txt'
        ext_bits = ''.join([bin(ord(c))[2:].zfill(8) for c in file_extension])
        ext_len = len(ext_bits)

        # Headers:
        # 1. 32 bits for extension length
        # 2. n bits for extension
        # 3. 32 bits for file length (in bytes)
        # 4. m bits for file content
        header_bits = bin(ext_len)[2:].zfill(32) + ext_bits + bin(file_bytes_length)[2:].zfill(32)
        all_bits = list(header_bits + file_bits)

        total_channels = flat_pixels.size
        if len(all_bits) > total_channels:
            raise ValueError("File too large for this image.")

        # Seed randomness
        random.seed(password)

        # Prepare randomized positions, excluding first bits used for header
        reserved_bits = len(header_bits)
        positions = list(range(reserved_bits, total_channels))
        random.shuffle(positions)

        # Combine header and shuffled message bits
        for i, bit in enumerate(all_bits):
            index = i if i < reserved_bits else positions[i - reserved_bits]
            pixel_byte = flat_pixels[index]
            new_byte = (pixel_byte & 0xFE) | int(bit)   # Replace LSB with bit
            flat_pixels[index] = new_byte

        # Save modified image
        new_data = flat_pixels.reshape(data.shape)
        Image.fromarray(new_data).save(output_path)
        
        # Clean up temporary file if created
        if not self.use_multiple_files.get() and self.is_hiding_image.get() and file_path.endswith("temp_processed_image.jpg"):
            try:
                os.remove(file_path)
            except:
                pass
    
    def extract_file_from_image(self, image_path, output_dir, password="mysecret"):
        """Extract hidden file from an image"""
        # Load image and flatten pixel data
        image = Image.open(image_path)
        data = asarray(image).copy()
        flat_pixels = data.reshape(-1, 3).reshape(-1)

        # Step 1: Read extension length (first 32 bits)
        ext_len_bits = ''.join([str(flat_pixels[i] & 1) for i in range(32)])
        ext_len = int(ext_len_bits, 2)

        # Step 2: Read extension bits
        ext_bits = ''.join([str(flat_pixels[i] & 1) for i in range(32, 32 + ext_len)])
        extension = ''.join([chr(int(ext_bits[i:i+8], 2)) for i in range(0, len(ext_bits), 8)])

        # Step 3: Read file length (next 32 bits)
        file_len_start = 32 + ext_len
        file_len_bits = ''.join([str(flat_pixels[i] & 1) for i in range(file_len_start, file_len_start + 32)])
        file_len = int(file_len_bits, 2)

        # Step 4: Generate same random positions
        reserved_bits = file_len_start + 32  # total bits used for header
        total_channels = flat_pixels.size
        positions = list(range(reserved_bits, total_channels))
        random.seed(password)
        random.shuffle(positions)   

        # Step 5: Extract hidden bits
        file_bits = ['0'] * (file_len * 8)
        for i in range(file_len * 8):
            pos = positions[i]
            file_bits[i] = str(flat_pixels[pos] & 1)

        # Step 6: Convert bits to bytes and save file
        byte_data = self.bits_to_bytes(''.join(file_bits))
        output_file = os.path.join(output_dir, f"extracted_file.{extension}")
        # Déchiffrer les données extraites
        try:
             decrypted_data = decrypt_data(byte_data, password)
        except Exception as e:
             raise ValueError("Mot de passe incorrect ou données corrompues.")

        with open(output_file, "wb") as f:
          f.write(decrypted_data)


        return output_file
    
    def __del__(self):
        """Clean up temporary directory when the application closes"""
        try:
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Error cleaning up temporary directory: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
