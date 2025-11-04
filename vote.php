<?php
require_once 'config.php';
requireLogin();

$conn = getDBConnection();
$user_id = $_SESSION['user_id'];
$election_id = isset($_GET['election_id']) ? intval($_GET['election_id']) : 0;
$message = '';
$error = '';

// Handle vote submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $position_id = intval($_POST['position_id']);
    $candidate_id = intval($_POST['candidate_id']);
    
    try {
        $stmt = $conn->prepare("CALL CastVote(?, ?, ?, ?)");
        $stmt->bind_param("iiis", $election_id, $position_id, $candidate_id, $user_id);
        $stmt->execute();
        $message = "Vote cast successfully!";
        $stmt->close();
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}

// Get election details
$election_query = "SELECT * FROM elections WHERE election_id = ? AND status = 'active'";
$election_stmt = $conn->prepare($election_query);
$election_stmt->bind_param("i", $election_id);
$election_stmt->execute();
$election = $election_stmt->get_result()->fetch_assoc();

if (!$election) {
    header("Location: index.php");
    exit();
}

// Get positions and candidates
$positions_query = "SELECT * FROM positions WHERE election_id = ? ORDER BY display_order";
$positions_stmt = $conn->prepare($positions_query);
$positions_stmt->bind_param("i", $election_id);
$positions_stmt->execute();
$positions_result = $positions_stmt->get_result();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vote - Student Voting System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <div class="container">
            <h1>Student Voting System</h1>
            <nav>
                <a href="index.php">Dashboard</a>
                <a href="my_votes.php">My Votes</a>
                <a href="results.php">Results</a>
                <a href="logout.php">Logout</a>
            </nav>
        </div>
    </header>
    
    <div class="container">
        <h2><?php echo htmlspecialchars($election['title']); ?></h2>
        <p><?php echo htmlspecialchars($election['description']); ?></p>
        
        <?php if ($message): ?>
            <div class="message success"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="message error"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php while ($position = $positions_result->fetch_assoc()): ?>
            <div class="card">
                <h3><?php echo htmlspecialchars($position['title']); ?></h3>
                <p><?php echo htmlspecialchars($position['description']); ?></p>
                
                <?php
                // Check if already voted for this position
                $vote_check_query = "SELECT c.candidate_id, u.name 
                    FROM votes v 
                    JOIN candidates c ON v.candidate_id = c.candidate_id 
                    JOIN users u ON c.user_id = u.user_id 
                    WHERE v.election_id = ? AND v.position_id = ? AND v.voter_id = ?";
                $vote_check_stmt = $conn->prepare($vote_check_query);
                $vote_check_stmt->bind_param("iis", $election_id, $position['position_id'], $user_id);
                $vote_check_stmt->execute();
                $existing_vote = $vote_check_stmt->get_result()->fetch_assoc();
                
                if ($existing_vote):
                ?>
                    <p style="color: #333; font-weight: bold;">✓ You voted for: <?php echo htmlspecialchars($existing_vote['name']); ?></p>
                <?php else: ?>
                    <?php
                    // Get candidates for this position
                    $candidates_query = "SELECT c.*, u.name, u.class 
                        FROM candidates c 
                        JOIN users u ON c.user_id = u.user_id 
                        WHERE c.position_id = ? AND c.is_active = 1";
                    $candidates_stmt = $conn->prepare($candidates_query);
                    $candidates_stmt->bind_param("i", $position['position_id']);
                    $candidates_stmt->execute();
                    $candidates_result = $candidates_stmt->get_result();
                    ?>
                    
                    <div class="candidate-list">
                        <?php while ($candidate = $candidates_result->fetch_assoc()): ?>
                            <div class="candidate-card">
                                <h4><?php echo htmlspecialchars($candidate['name']); ?></h4>
                                <p><strong>Class:</strong> <?php echo htmlspecialchars($candidate['class']); ?></p>
                                <p><strong>Bio:</strong> <?php echo htmlspecialchars($candidate['short_bio']); ?></p>
                                <p><em>"<?php echo htmlspecialchars($candidate['campaign_message']); ?>"</em></p>
                                
                                <form method="POST" action="">
                                    <input type="hidden" name="position_id" value="<?php echo $position['position_id']; ?>">
                                    <input type="hidden" name="candidate_id" value="<?php echo $candidate['candidate_id']; ?>">
                                    <button type="submit">Vote for <?php echo htmlspecialchars($candidate['name']); ?></button>
                                </form>
                            </div>
                        <?php endwhile; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endwhile; ?>
        
        <div class="text-center mt-20">
            <a href="index.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>
    </div>
    
    <footer>
        <p>&copy; BSIT 2A 2025 Student Voting System</p>
    </footer>
</body>
</html>
<?php $conn->close(); ?>