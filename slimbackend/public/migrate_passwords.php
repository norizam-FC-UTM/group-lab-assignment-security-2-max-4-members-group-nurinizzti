<?php
// 1. Include the file that defines your getPDO() function
require_once __DIR__ . '/../src/db.php'; 

// 2. CALL the function to get the actual object!
$pdo = getPDO(); 

// 3. Now you can use it
$users = $pdo->query("SELECT id, password FROM users")->fetchAll();

foreach ($users as $user) {
    $hashed = password_hash($user['password'], PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
    $stmt->execute([$hashed, $user['id']]);
}

echo "Migration complete! All passwords have been hashed.";
?>