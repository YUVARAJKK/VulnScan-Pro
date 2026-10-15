<?php
// Deliberately vulnerable SQL injection test app (for scanner verification only)
if (isset($_GET['id'])) {
    $pdo = new PDO('sqlite::memory:');
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INT, name TEXT)");
    $pdo->exec("INSERT OR IGNORE INTO users VALUES (1, 'admin')");
    try {
        $stmt = $pdo->query("SELECT name FROM users WHERE id = " . $_GET['id']);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        echo "Hello " . $row['name'];
    } catch (PDOException $e) {
        // Error-based SQLi sink: exposes the SQL error message
        echo "DB Error: " . $e->getMessage();
    }
}
?>
