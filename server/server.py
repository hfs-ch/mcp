from pathlib import Path
import logging
import base64

from mcp.server import MCPServer


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

SANDBOX = (BASE_DIR / "sandbox").resolve()

SECURITY_LOG = BASE_DIR / "security.log"


# ============================================================
# PROTECTED FILES
# ============================================================

PROTECTED_FILES = {
    "private.txt",
    "secret.txt",
    ".env",
    "security.log",
}


# ============================================================
# ALLOWED EXTENSIONS
# ============================================================

ALLOWED_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".log",
}

ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
}

ALLOWED_DOCUMENT_EXTENSIONS = {
    ".pdf",
}


# ============================================================
# MCP SERVER
# ============================================================

mcp = MCPServer(
    "MCP Secure Workspace"
)


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("mcp-server")

logger.setLevel(logging.INFO)

if not logger.handlers:

    handler = logging.FileHandler(
        SECURITY_LOG,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    handler.setFormatter(formatter)

    logger.addHandler(handler)


# ============================================================
# SECURITY HELPERS
# ============================================================

def is_protected_file(filename: str) -> bool:

    name = Path(filename).name.lower()

    return name in {
        item.lower()
        for item in PROTECTED_FILES
    }


def resolve_safe_path(filename: str):

    if not filename:
        return None

    requested = (
        SANDBOX / filename
    ).resolve()

    try:

        requested.relative_to(
            SANDBOX
        )

    except ValueError:

        logger.warning(
            "SECURITY_EVENT=PATH_TRAVERSAL | filename=%s",
            filename
        )

        return None

    return requested


def is_symlink(filename: str) -> bool:

    original = SANDBOX / filename

    return original.is_symlink()


def file_exists(path: Path) -> bool:

    return path.exists() and path.is_file()


def is_extension_allowed(
    path: Path,
    extensions: set[str]
) -> bool:

    return path.suffix.lower() in extensions


# ============================================================
# LIST FILES
# ============================================================

@mcp.tool()
def list_files() -> list[str]:
    """
    List non-protected files available
    inside the secure sandbox.
    """

    files = []

    if not SANDBOX.exists():
        return files

    for file in SANDBOX.rglob("*"):

        if not file.is_file():
            continue

        if file.is_symlink():
            continue

        if is_protected_file(
            str(file.relative_to(SANDBOX))
        ):
            continue

        try:

            relative = file.relative_to(
                SANDBOX
            )

        except ValueError:

            continue

        files.append(
            str(relative)
        )

    logger.info(
        "FILE_LIST | count=%s",
        len(files)
    )

    return sorted(files)


# ============================================================
# READ TEXT FILE
# ============================================================

@mcp.tool()
def read_file(filename: str) -> str:
    """
    Read a text file securely.
    """

    # --------------------------------------------------------
    # PROTECTED FILE
    # --------------------------------------------------------

    if is_protected_file(filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_FILE_ACCESS | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "protected file."
        )


    # --------------------------------------------------------
    # PATH VALIDATION
    # --------------------------------------------------------

    path = resolve_safe_path(
        filename
    )

    if path is None:

        return (
            "SECURITY BLOCK: "
            "path traversal detected."
        )


    # --------------------------------------------------------
    # SYMLINK
    # --------------------------------------------------------

    if is_symlink(filename):

        logger.warning(
            "SECURITY_EVENT=SYMLINK_ESCAPE | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "symbolic links are not allowed."
        )


    # --------------------------------------------------------
    # FILE EXISTS
    # --------------------------------------------------------

    if not file_exists(path):

        return "File not found."


    # --------------------------------------------------------
    # EXTENSION
    # --------------------------------------------------------

    if not is_extension_allowed(
        path,
        ALLOWED_TEXT_EXTENSIONS
    ):

        logger.warning(
            "SECURITY_EVENT=UNAUTHORIZED_EXTENSION | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "file type is not allowed."
        )


    # --------------------------------------------------------
    # READ
    # --------------------------------------------------------

    try:

        content = path.read_text(
            encoding="utf-8"
        )

    except UnicodeDecodeError:

        return (
            "Error: file is not valid UTF-8."
        )


    logger.info(
        "FILE_READ | filename=%s",
        filename
    )

    return content


# ============================================================
# READ IMAGE
# ============================================================

@mcp.tool()
def read_image(filename: str) -> str:
    """
    Read an image securely.
    """

    if is_protected_file(filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_FILE_ACCESS | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "protected file."
        )


    path = resolve_safe_path(
        filename
    )

    if path is None:

        return (
            "SECURITY BLOCK: "
            "path traversal detected."
        )


    if is_symlink(filename):

        logger.warning(
            "SECURITY_EVENT=SYMLINK_ESCAPE | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "symbolic links are not allowed."
        )


    if not file_exists(path):

        return "Image not found."


    if not is_extension_allowed(
        path,
        ALLOWED_IMAGE_EXTENSIONS
    ):

        return (
            "SECURITY BLOCK: "
            "invalid image format."
        )


    try:

        data = path.read_bytes()

        encoded = base64.b64encode(
            data
        ).decode("utf-8")

    except Exception as exc:

        logger.exception(
            "SECURITY_EVENT=IMAGE_READ_ERROR | %s",
            exc
        )

        return "Unable to read image."


    logger.info(
        "IMAGE_READ | filename=%s",
        filename
    )

    return (
        f"IMAGE_BASE64:{encoded}"
    )


# ============================================================
# READ PDF
# ============================================================

@mcp.tool()
def read_pdf(filename: str) -> str:
    """
    Read a PDF securely.
    """

    if is_protected_file(filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_FILE_ACCESS | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "protected file."
        )


    path = resolve_safe_path(
        filename
    )

    if path is None:

        return (
            "SECURITY BLOCK: "
            "path traversal detected."
        )


    if is_symlink(filename):

        logger.warning(
            "SECURITY_EVENT=SYMLINK_ESCAPE | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "symbolic links are not allowed."
        )


    if not file_exists(path):

        return "PDF not found."


    if not is_extension_allowed(
        path,
        ALLOWED_DOCUMENT_EXTENSIONS
    ):

        return (
            "SECURITY BLOCK: "
            "file is not a PDF."
        )


    try:

        import PyPDF2

        reader = PyPDF2.PdfReader(
            str(path)
        )

        pages = []

        for page in reader.pages:

            text = page.extract_text()

            if text:

                pages.append(text)


        content = "\n".join(
            pages
        )

    except ImportError:

        return (
            "PDF support requires PyPDF2."
        )

    except Exception as exc:

        logger.exception(
            "SECURITY_EVENT=PDF_READ_ERROR | %s",
            exc
        )

        return "Unable to read PDF."


    logger.info(
        "PDF_READ | filename=%s",
        filename
    )

    return content


# ============================================================
# RENAME FILE
# ============================================================

@mcp.tool()
def rename_file(
    old_filename: str,
    new_filename: str
) -> str:
    """
    Rename a file securely.
    """

    # --------------------------------------------------------
    # PROTECTED SOURCE
    # --------------------------------------------------------

    if is_protected_file(old_filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_RENAME_SOURCE | filename=%s",
            old_filename
        )

        return (
            "SECURITY BLOCK: "
            "protected file cannot be renamed."
        )


    # --------------------------------------------------------
    # PROTECTED DESTINATION
    # --------------------------------------------------------

    if is_protected_file(new_filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_RENAME_DESTINATION | filename=%s",
            new_filename
        )

        return (
            "SECURITY BLOCK: "
            "cannot rename to a protected filename."
        )


    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    old_path = resolve_safe_path(
        old_filename
    )

    new_path = resolve_safe_path(
        new_filename
    )


    if old_path is None or new_path is None:

        logger.warning(
            "SECURITY_EVENT=PATH_TRAVERSAL_RENAME | "
            "old=%s | new=%s",
            old_filename,
            new_filename
        )

        return (
            "SECURITY BLOCK: "
            "invalid path."
        )


    # --------------------------------------------------------
    # SYMLINK
    # --------------------------------------------------------

    if is_symlink(old_filename):

        return (
            "SECURITY BLOCK: "
            "symbolic links cannot be renamed."
        )


    # --------------------------------------------------------
    # SOURCE
    # --------------------------------------------------------

    if not file_exists(old_path):

        return "Source file not found."


    # --------------------------------------------------------
    # DESTINATION
    # --------------------------------------------------------

    if new_path.exists():

        return (
            "SECURITY BLOCK: "
            "destination already exists."
        )


    # --------------------------------------------------------
    # RENAME
    # --------------------------------------------------------

    try:

        old_path.rename(
            new_path
        )

    except Exception as exc:

        logger.exception(
            "SECURITY_EVENT=RENAME_ERROR | %s",
            exc
        )

        return "Unable to rename file."


    logger.info(
        "FILE_RENAMED | old=%s | new=%s",
        old_filename,
        new_filename
    )

    return (
        f"File renamed successfully: "
        f"{old_filename} -> {new_filename}"
    )


# ============================================================
# DELETE FILE
# ============================================================

@mcp.tool()
def delete_file(
    filename: str,
    confirmation: str = ""
) -> str:
    """
    Delete a file securely.
    Explicit confirmation is required.
    """

    # --------------------------------------------------------
    # PROTECTED FILE
    # --------------------------------------------------------

    if is_protected_file(filename):

        logger.warning(
            "SECURITY_EVENT=PROTECTED_DELETE | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "protected file cannot be deleted."
        )


    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    path = resolve_safe_path(
        filename
    )

    if path is None:

        return (
            "SECURITY BLOCK: "
            "path traversal detected."
        )


    # --------------------------------------------------------
    # SYMLINK
    # --------------------------------------------------------

    if is_symlink(filename):

        logger.warning(
            "SECURITY_EVENT=SYMLINK_DELETE_BLOCKED | filename=%s",
            filename
        )

        return (
            "SECURITY BLOCK: "
            "symbolic links cannot be deleted."
        )


    # --------------------------------------------------------
    # FILE
    # --------------------------------------------------------

    if not file_exists(path):

        return "File not found."


    # --------------------------------------------------------
    # CONFIRMATION
    # --------------------------------------------------------

    if confirmation != "CONFIRM DELETE":

        logger.warning(
            "SECURITY_EVENT=DELETE_CONFIRMATION_REQUIRED | filename=%s",
            filename
        )

        return (
            "DELETE BLOCKED: "
            "explicit confirmation required."
        )


    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    try:

        path.unlink()

    except Exception as exc:

        logger.exception(
            "SECURITY_EVENT=DELETE_ERROR | %s",
            exc
        )

        return "Unable to delete file."


    logger.warning(
        "SECURITY_EVENT=FILE_DELETED | filename=%s",
        filename
    )

    return (
        f"File deleted successfully: "
        f"{filename}"
    )


# ============================================================
# SERVER START
# ============================================================

if __name__ == "__main__":
    import sys

    print(
        "MCP Secure Workspace Server",
        file=sys.stderr
    )

    print(
        f"Sandbox: {SANDBOX}",
        file=sys.stderr
    )

    mcp.run()