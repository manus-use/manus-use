"""Tests for tools module."""

import pytest
from pathlib import Path
import tempfile

from manus_use.tools import (
    file_read, file_write, file_list, file_delete, file_move,
    get_tools_by_names
)


def test_file_read_write(tmp_path):
    """Test file read and write operations."""
    # Write a file
    test_file = tmp_path / "test.txt"
    content = "Hello, ManusUse!"
    
    result = file_write(str(test_file), content)
    assert "Successfully wrote" in result
    
    # Read the file
    read_content = file_read(str(test_file))
    assert read_content == content


def test_file_list(tmp_path):
    """Test file listing."""
    # Create some test files
    (tmp_path / "file1.txt").write_text("content1")
    (tmp_path / "file2.py").write_text("content2")
    (tmp_path / "subdir").mkdir()
    
    # List all files
    files = file_list(str(tmp_path))
    assert len(files) == 3
    assert "file1.txt" in files
    assert "file2.py" in files
    assert "subdir" in files
    
    # List with pattern
    py_files = file_list(str(tmp_path), "*.py")
    assert len(py_files) == 1
    assert "file2.py" in py_files


def test_file_delete(tmp_path):
    """Test file deletion."""
    # Create and delete a file
    test_file = tmp_path / "delete_me.txt"
    test_file.write_text("delete this")
    
    result = file_delete(str(test_file))
    assert "Deleted file" in result
    assert not test_file.exists()
    
    # Delete empty directory
    test_dir = tmp_path / "empty_dir"
    test_dir.mkdir()
    
    result = file_delete(str(test_dir))
    assert "Deleted empty directory" in result
    assert not test_dir.exists()


def test_file_move(tmp_path):
    """Test file move/rename."""
    # Create source file
    src = tmp_path / "source.txt"
    src.write_text("move me")
    
    dst = tmp_path / "destination.txt"
    
    result = file_move(str(src), str(dst))
    assert "Moved" in result
    assert not src.exists()
    assert dst.exists()
    assert dst.read_text() == "move me"


def test_get_tools_by_names():
    """Test tool retrieval by names."""
    tools = get_tools_by_names(["file_read", "file_write"])
    assert len(tools) == 2
    
    # Check that we got the right tools
    tool_names = [t.__name__ for t in tools]
    assert "file_read" in tool_names
    assert "file_write" in tool_names


def test_file_errors():
    """Test error handling in file operations."""
    # Read non-existent file
    with pytest.raises(FileNotFoundError):
        file_read("/non/existent/file.txt")
        
    # List non-existent directory
    with pytest.raises(FileNotFoundError):
        file_list("/non/existent/directory")
        
    # Delete non-existent file
    with pytest.raises(FileNotFoundError):
        file_delete("/non/existent/file.txt")
        
    # Move non-existent file
    with pytest.raises(FileNotFoundError):
        file_move("/non/existent/source.txt", "/tmp/dest.txt")