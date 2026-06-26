<?php
// ==========================================================
// SECJ3483 Web Technology
// Person BMI Slim Backend - Member 1 Safe Phase Integration
// ==========================================================
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/db.php';

$app = AppFactory::create();

// Required for JSON/form body parsing in Slim 4.
$app->addBodyParsingMiddleware();

// Helpful for development error display.
$app->addErrorMiddleware(false, true, true);

// ----------------------------------------------------------
// CORS for Vue CLI frontend
// ----------------------------------------------------------
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    return $response
        ->withHeader('Access-Control-Allow-Origin', '*') 
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'false');
});

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------
function jsonResponse(Response $response, $data, int $status = 200): Response
{
    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));

    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status);
}

function getRequestData(Request $request): array
{
    $data = $request->getParsedBody();

    if (is_array($data) && !empty($data)) {
        return $data;
    }

    $rawBody = (string) $request->getBody();

    if ($rawBody !== '') {
        $jsonData = json_decode($rawBody, true);

        if (is_array($jsonData)) {
            return $jsonData;
        }
    }

    return is_array($data) ? $data : [];
}

function getJwtSecret(): string
{
    $secret = getenv('JWT_SECRET');

    if (!is_string($secret) || $secret === '') {
        $secret = 'change-me-in-production-at-least-32-characters-long';
    }

    return $secret;
}

function createJwt(array $user): string
{
    $now = time();
    $payload = [
        'user_id' => (int)($user['id'] ?? 0),
        'role' => $user['role'] ?? 'user',
        'email' => $user['email'] ?? '',
        'iat' => $now,
        'exp' => $now + 3600
    ];

    return JWT::encode($payload, getJwtSecret(), 'HS256');
}

function verifyTokenFromRequest(Request $request): ?array
{
    $auth = $request->getHeaderLine('Authorization');

    if (!$auth || !preg_match('/Bearer\s+(\S+)/', $auth, $matches)) {
        return null;
    }

    try {
        $decoded = JWT::decode($matches[1], new Key(getJwtSecret(), 'HS256'));
        $payload = json_decode(json_encode($decoded), true);

        return is_array($payload) ? $payload : null;
    } catch (Throwable $e) {
        return null;
    }
}

function exposeException(Response $response, Throwable $e): Response
{
    error_log(sprintf('API error: %s in %s:%d', $e->getMessage(), $e->getFile(), $e->getLine()));

    return jsonResponse($response, [
        'error' => 'Internal server error'
    ], 500);
}

// ==========================================================
// MEMBER 1 FIX 2: Server-Side BMI Calculation Engines
// ==========================================================
function calculateBmi($height, $weight) {
    return round($weight / ($height * $height), 2);
}

function getBmiCategory($bmi) {
    if ($bmi < 18.5) {
        return "Underweight";
    } elseif ($bmi < 25.0) {
        return "Normal";
    } elseif ($bmi < 30.0) {
        return "Overweight";
    } else {
        return "Obese";
    }
}

// ----------------------------------------------------------
// Root routes 
// ----------------------------------------------------------
$app->get('/', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'message' => 'Person BMI Backend - Member 1 Foundation Integration Active.',
        'warning' => 'Core DB drivers secured. Route firewalls are open for Member 2.'
    ]);
});

$app->get('/api/health', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'status' => 'ok',
        'api' => 'person-bmi-secured-db-drivers'
    ]);
});

// ----------------------------------------------------------
// Public route: Register
// ----------------------------------------------------------
$app->post('/api/register', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $name = $data['name'] ?? '';
        $email = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';
        $role = $data['role'] ?? 'user';

        if ($email === '') {
            return jsonResponse($response, ['error' => 'Email is required'], 400);
        }

        // Check if email already exists
        $stmtCheck = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmtCheck->execute([$email]);
        if ($stmtCheck->fetch()) {
            return jsonResponse($response, ['error' => 'Email is already registered'], 400);
        }

        // MEMBER 1 FIX 3: Cryptographic Password Hashing Strategy
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // MEMBER 1 FIX 4: PDO Prepared Statements parameter injection block
        $sql = "INSERT INTO users (name, email, password, password_hash, role)
                VALUES (:name, :email, :plain_placeholder, :password_hash, :role)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':name'              => $name,
            ':email'             => $email,
            ':plain_placeholder' => null, // Stop storing plain-text strings entirely
            ':password_hash'     => $passwordHash,
            ':role'              => $role
        ]);
        
        $id = $pdo->lastInsertId();

        // Safe fetch with parameter bindings
        $stmtFetch = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
        $stmtFetch->execute([$id]);
        $user = $stmtFetch->fetch();

        return jsonResponse($response, [
            'message' => 'User registered with hashed credentials.',
            'user' => $user
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Public route: Login (FIXED FOR MISSION 7 AFTER-FIX)
// ----------------------------------------------------------
$app->post('/api/login', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $email = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';

        // MEMBER 1 FIX 4: Parameterized execution prevents SQL Injection (' OR '1'='1)
        $sql = "SELECT * FROM users WHERE email = ? LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // MEMBER 1 FIX 3: Safe timing-attack resistant password validation
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return jsonResponse($response, [
                'error' => 'Invalid email or password'
            ], 401);
        }

        $token = createJwt($user);

        // Remove sensitive fields before returning user data
        unset($user['password']);
        unset($user['password_hash']);

        return jsonResponse($response, [
            'message' => 'Login successful. Secure password verification confirmed.',
            'token' => $token,
            'user' => $user 
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Protected-ish route: Profile
// ----------------------------------------------------------
$app->get('/api/profile', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $userId = $tokenPayload['user_id'] ?? null;

        if (!$userId) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        // MEMBER 1 FIX 4: Prepared parameter lookup
        $stmt = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'Profile returned using prepared database statements.',
            'user' => $user,
            'token_payload_trusted_by_backend' => $tokenPayload
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// BMI routes
// ----------------------------------------------------------
$app->get('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $userRole = $tokenPayload['role'] ?? 'user';
        if ($userRole !== 'admin' && $userRole !== 'staff') {
            $userId = (int)$tokenPayload['user_id'];
        } else {
            $params = $request->getQueryParams();
            $userId = isset($params['user_id']) ? (int)$params['user_id'] : null;
        }

        // MEMBER 1 FIX 4: Applied prepared structures to filter collections safely
        if ($userId) {
            $stmt = $pdo->prepare("SELECT * FROM persons WHERE user_id = ? ORDER BY id DESC");
            $stmt->execute([$userId]);
        } else {
            $stmt = $pdo->prepare("SELECT * FROM persons ORDER BY id DESC");
            $stmt->execute();
        }

        $persons = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'BMI records returned safely via parameter binding mapping.',
            'persons' => $persons
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->post('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $data = getRequestData($request);

        // ==========================================
        // MEMBER 1 FIX 1: STRICT DATA RANGE CHECKING
        // ==========================================
        if (!isset($data['name']) || trim($data['name']) === '') {
            return jsonResponse($response, ["error" => "Name is required"], 400);
        }
        if (!isset($data['age']) || $data['age'] < 1 || $data['age'] > 120) {
            return jsonResponse($response, ["error" => "Age must be between 1 and 120"], 400);
        }
        if (!isset($data['height']) || $data['height'] < 0.5 || $data['height'] > 2.5) {
            return jsonResponse($response, ["error" => "Height must be between 0.5 and 2.5 meters"], 400);
        }
        if (!isset($data['weight']) || $data['weight'] < 2 || $data['weight'] > 300) {
            return jsonResponse($response, ["error" => "Weight must be between 2 and 300 kg"], 400);
        }

        // ==========================================
        // MEMBER 1 FIX 2: ISOLATED BACKEND BUSINESS METRICS
        // ==========================================
        $height = (float)$data['height'];
        $weight = (float)$data['weight'];
        
        // Dynamic server-side execution eliminates metric spoofing
        $bmi = calculateBmi($height, $weight);
        $category = getBmiCategory($bmi);

        $userRole = $tokenPayload['role'] ?? 'user';
        if ($userRole !== 'admin' && $userRole !== 'staff') {
            $user_id = (int)$tokenPayload['user_id'];
        } else {
            $user_id = isset($data['user_id']) ? (int)$data['user_id'] : (int)$tokenPayload['user_id'];
        }
        $name = trim($data['name']);
        $age = (int)$data['age'];
        $notes = $data['notes'] ?? '';

        // MEMBER 1 FIX 4: Injection resilient structure map
        $sql = "INSERT INTO persons (user_id, name, age, height, weight, bmi, category, notes)
                VALUES (:user_id, :name, :age, :height, :weight, :bmi, :category, :notes)";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':user_id'  => $user_id,
            ':name'     => $name,
            ':age'      => $age,
            ':height'   => $height,
            ':weight'   => $weight,
            ':bmi'      => $bmi,
            ':category' => $category,
            ':notes'    => $notes
        ]);
        
        $id = $pdo->lastInsertId();

        $stmtFetch = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmtFetch->execute([$id]);

        return jsonResponse($response, [
            'message' => 'BMI record created securely via server processing arrays.',
            'person' => $stmtFetch->fetch()
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $id = $args['id'];

        // MEMBER 1 FIX 4: Single entity bind mapping
        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // Fix 7: Owner-Based Access Control check
        $userRole = $tokenPayload['role'] ?? 'user';
        if ($userRole !== 'admin' && $userRole !== 'staff') {
            if ((int)$person['user_id'] !== (int)$tokenPayload['user_id']) {
                return jsonResponse($response, ['error' => 'Forbidden'], 403);
            }
        }

        return jsonResponse($response, [
            'message' => 'Record single item lookup loaded with parameter drivers.',
            'person' => $person
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $id = $args['id'];
        $data = getRequestData($request);

        // Fetch original record using prepared lookup to check existing fields if needed
        $stmtOrig = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmtOrig->execute([$id]);
        $originalPerson = $stmtOrig->fetch();

        if (!$originalPerson) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // Fix 7: Owner-Based Access Control check
        $userRole = $tokenPayload['role'] ?? 'user';
        if ($userRole !== 'admin' && $userRole !== 'staff') {
            if ((int)$originalPerson['user_id'] !== (int)$tokenPayload['user_id']) {
                return jsonResponse($response, ['error' => 'Forbidden'], 403);
            }
        }

        // Strict range validation for updated fields
        if (array_key_exists('name', $data) && (!isset($data['name']) || trim($data['name']) === '')) {
            return jsonResponse($response, ["error" => "Name is required"], 400);
        }
        if (array_key_exists('age', $data) && (!isset($data['age']) || $data['age'] < 1 || $data['age'] > 120)) {
            return jsonResponse($response, ["error" => "Age must be between 1 and 120"], 400);
        }
        if (array_key_exists('height', $data) && (!isset($data['height']) || $data['height'] < 0.5 || $data['height'] > 2.5)) {
            return jsonResponse($response, ["error" => "Height must be between 0.5 and 2.5 meters"], 400);
        }
        if (array_key_exists('weight', $data) && (!isset($data['weight']) || $data['weight'] < 2 || $data['weight'] > 300)) {
            return jsonResponse($response, ["error" => "Weight must be between 2 and 300 kg"], 400);
        }

        // Fix 9: Mass Assignment Prevention using $allowedFields filter whitelist
        $allowedFields = ['name', 'age', 'height', 'weight', 'notes'];

        $sets = [];
        $params = [];

        foreach ($allowedFields as $field) {
            if (array_key_exists($field, $data)) {
                $sets[] = "$field = ?";
                $params[] = $data[$field];
            }
        }

        // Recalculate BMI and category on backend if height or weight is updated
        if (array_key_exists('height', $data) || array_key_exists('weight', $data)) {
            $height = isset($data['height']) ? (float)$data['height'] : (float)$originalPerson['height'];
            $weight = isset($data['weight']) ? (float)$data['weight'] : (float)$originalPerson['weight'];
            
            $bmi = calculateBmi($height, $weight);
            $category = getBmiCategory($bmi);
            
            $sets[] = "bmi = ?";
            $params[] = $bmi;
            
            $sets[] = "category = ?";
            $params[] = $category;
        }

        if (!$sets) {
            return jsonResponse($response, ['error' => 'No fields to update'], 400);
        }

        // MEMBER 1 FIX 4: Dynamic statement processing converted to safe binding tokens
        $sql = "UPDATE persons SET " . implode(', ', $sets) . " WHERE id = ?";
        $params[] = $id; // Append criteria tracking target to parameter list
        
        $stmtUpdate = $pdo->prepare($sql);
        $stmtUpdate->execute($params);

        $stmtCheck = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmtCheck->execute([$id]);

        return jsonResponse($response, [
            'message' => 'BMI record drivers updated securely via strict statement mapping array execution.',
            'person' => $stmtCheck->fetch()
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        $id = $args['id'];

        // Fetch the record first to verify existence and check ownership
        $stmtCheck = $pdo->prepare("SELECT * FROM persons WHERE id = ?");
        $stmtCheck->execute([$id]);
        $person = $stmtCheck->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // Fix 7: Owner-Based Access Control check
        $userRole = $tokenPayload['role'] ?? 'user';
        if ($userRole !== 'admin' && $userRole !== 'staff') {
            if ((int)$person['user_id'] !== (int)$tokenPayload['user_id']) {
                return jsonResponse($response, ['error' => 'Forbidden'], 403);
            }
        }


        // MEMBER 1 FIX 4: Prepared statement parameter isolation locks delete actions safely
        $stmt = $pdo->prepare("DELETE FROM persons WHERE id = ?");
        $stmt->execute([$id]);

        return jsonResponse($response, [
            'message' => 'BMI record removed using secure structural criteria parameter execution.'
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Staff routes
// ----------------------------------------------------------
$app->get('/api/staff/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        if (($tokenPayload['role'] ?? '') !== 'staff' && ($tokenPayload['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden'], 403);
        }

        // MEMBER 1 FIX 4: Joint analytical processing parameterized safely
        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                ORDER BY persons.id DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $persons = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'All structural system data arrays loaded securely via static statement pipelines.',
            'persons' => $persons
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/staff/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        if (($tokenPayload['role'] ?? '') !== 'staff' && ($tokenPayload['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden'], 403);
        }

        $id = $args['id'];

        // MEMBER 1 FIX 4: Parameter mapping for diagnostic single targets
        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                WHERE persons.id = ?";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        return jsonResponse($response, [
            'message' => 'Structural tracking record mapping item pulled cleanly.',
            'person' => $person
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Admin routes
// ----------------------------------------------------------
$app->get('/api/admin/users', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        if (($tokenPayload['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden'], 403);
        }

        // UNTOUCHED SENSITIVE EXPOSURE: Left open for Member 3 to drop password/password_hash fields from tracking metrics
        $sql = "SELECT id, name, email, role, created_at FROM users ORDER BY id ASC";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        $users = $stmt->fetchAll();

        return jsonResponse($response, [
            'message' => 'User registry metrics array generated safely via driver queries.',
            'users' => $users
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/admin/users/{id}/role', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        if (($tokenPayload['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden'], 403);
        }

        $id = $args['id'];
        $data = getRequestData($request);
        $role = $data['role'] ?? 'user';

        // MEMBER 1 FIX 4: Protected administrative updates against SQL injection anomalies
        $sql = "UPDATE users SET role = ? WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$role, $id]);

        $stmtFetch = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
        $stmtFetch->execute([$id]);

        return jsonResponse($response, [
            'message' => 'User account configuration adjusted securely.',
            'user' => $stmtFetch->fetch()
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/admin/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        $tokenPayload = verifyTokenFromRequest($request);

        if (!$tokenPayload) {
            return jsonResponse($response, ['error' => 'Unauthorized'], 401);
        }

        if (($tokenPayload['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden'], 403);
        }

        $id = $args['id'];

        // MEMBER 1 FIX 4: Parameter isolation strategy applied cleanly
        $sql = "DELETE FROM persons WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$id]);

        return jsonResponse($response, [
            'message' => 'Administrative targeted execution block removed safely.'
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// Preflight catch-all
$app->options('/{routes:.+}', function (Request $request, Response $response) {
    return $response;
});

$app->run();