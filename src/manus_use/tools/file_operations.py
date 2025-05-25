"""File operation tools for ManusUse."""

import os
import shutil
from pathlib import Path
from typing import List, Optional

from strands import tool


@tool
def file_read(file_path: str) -> str:
    """Read contents of a file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        Contents of the file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file cannot be read
    """
    path = Path(file_path).expanduser().resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
        
    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
        
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Try reading as binary and return hex representation
        content = path.read_bytes()
        return f"Binary file ({len(content)} bytes): {content[:100].hex()}..."


@tool
def file_write(file_path: str, content: str, create_dirs: bool = True) -> str:
    """Write content to a file.
    
    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        create_dirs: Whether to create parent directories if they don't exist
        
    Returns:
        Success message with file path
        
    Raises:
        PermissionError: If file cannot be written
    """
    path = Path(file_path).expanduser().resolve()
    
    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)
        
    try:
        path.write_text(content, encoding="utf-8")
        return f"Successfully wrote {len(content)} characters to {file_path}"
    except Exception as e:
        raise RuntimeError(f"Failed to write file: {str(e)}")


@tool
def file_list(directory: str = ".", pattern: Optional[str] = None) -> List[str]:
    """List files in a directory.
    
    Args:
        directory: Directory path to list (defaults to current directory)
        pattern: Optional glob pattern to filter files (e.g., "*.py")
        
    Returns:
        List of file paths relative to the directory
        
    Raises:
        FileNotFoundError: If directory doesn't exist
    """
    path = Path(directory).expanduser().resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
        
    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {directory}")
        
    try:
        if pattern:
            files = list(path.glob(pattern))
        else:
            files = list(path.iterdir())
            
        # Return relative paths as strings
        return [str(f.relative_to(path)) for f in files]
    except Exception as e:
        raise RuntimeError(f"Failed to list directory: {str(e)}")


@tool
def file_delete(file_path: str, force: bool = False) -> str:
    """Delete a file or directory.
    
    Args:
        file_path: Path to the file or directory to delete
        force: If True, delete directories recursively
        
    Returns:
        Success message
        
    Raises:
        FileNotFoundError: If path doesn't exist
        PermissionError: If path cannot be deleted
    """
    path = Path(file_path).expanduser().resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {file_path}")
        
    try:
        if path.is_file():
            path.unlink()
            return f"Deleted file: {file_path}"
        elif path.is_dir():
            if force:
                shutil.rmtree(path)
                return f"Deleted directory recursively: {file_path}"
            else:
                path.rmdir()
                return f"Deleted empty directory: {file_path}"
    except Exception as e:
        raise RuntimeError(f"Failed to delete: {str(e)}")


@tool
def file_move(source: str, destination: str, overwrite: bool = False) -> str:
    """Move or rename a file or directory.
    
    Args:
        source: Source path
        destination: Destination path
        overwrite: Whether to overwrite if destination exists
        
    Returns:
        Success message
        
    Raises:
        FileNotFoundError: If source doesn't exist
        FileExistsError: If destination exists and overwrite is False
    """
    src_path = Path(source).expanduser().resolve()
    dst_path = Path(destination).expanduser().resolve()
    
    if not src_path.exists():
        raise FileNotFoundError(f"Source not found: {source}")
        
    if dst_path.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {destination}")
        
    try:
        # Create parent directory if needed
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use shutil.move for cross-filesystem moves
        shutil.move(str(src_path), str(dst_path))
        return f"Moved {source} to {destination}"
    except Exception as e:
        raise RuntimeError(f"Failed to move: {str(e)}")