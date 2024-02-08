<?php
//SQLi Protection - This code block handles protection against SQL injection attacks.
if ($settings['sqli_protection'] == 1) {

    //XSS Protection - Block infected requests (commented out for now)
    //@header("X-XSS-Protection: 1; mode=block");

    //XSS Protection - Sanitize infected requests (if enabled)
    if ($settings['sqli_protection2'] == 1) {
        @header("X-XSS-Protection: 1");
    }

    //Clickjacking Protection (if enabled)
    if ($settings['sqli_protection3'] == 1) {
        @header("X-Frame-Options: sameorigin");
    }

    //Prevents attacks based on MIME-type mismatch (if enabled)
    if ($settings['sqli_protection4'] == 1) {
        @header("X-Content-Type-Options: nosniff");
    }

    //Force secure connection using HSTS (HTTP Strict Transport Security) (if enabled)
    if ($settings['sqli_protection5'] == 1) {
        @header("Strict-Transport-Security: max-age=15552000; preload");
    }

    //Hide PHP Version (if enabled)
    if ($settings['sqli_protection6'] == 1) {
        @header('X-Powered-By: Project SECURITY');
    }

    //Sanitize all incoming data (GET, POST, REQUEST, COOKIE, and SESSION) (if enabled)
    if ($settings['sqli_protection7'] == 1) {
        $_GET  = filter_input_array(INPUT_GET, FILTER_SANITIZE_SPECIAL_CHARS);
        $_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_SPECIAL_CHARS);
    }

    //Data Sanitization (if enabled)
    if ($settings['sqli_protection8'] == 1) {

        // Function to clean malicious input from data
        if (!function_exists('cleanInput')) {
            function cleanInput($input)
            {
                $search = array(
                    '@<script[^>]*?>.*?</script>@si', // Strip out javascript
                    '@<[\/\!]*?[^<>]*?>@si', // Strip out HTML and PHP tags
                    '@<style[^>]*?>.*?</style>@siU', // Strip style tags properly
                    '@<![\s\S]*?--[ \t\n\r]*>@' // Strip multi-line comments
                );

                $output = preg_replace($search, '', $input);
                return $output;
            }
        }

        // Function to sanitize input data to prevent attacks
        if (!function_exists('sanitize')) {
            function sanitize($input)
            {
                if (is_array($input)) {
                    $output = [];
                    foreach ($input as $var => $val) {
                        $output[$var] = sanitize($val);
                    }
                } else {
                    $output = '';
                    if ($input == NULL) {
                        $input = '';
                    }
                    $input  = str_replace('"', "", $input);
                    $input  = str_replace("'", "", $input);
                    $input  = cleanInput($input);
                    $output = htmlentities($input, ENT_QUOTES);
                }
                return @$output;
            }
        }

        // Apply data sanitization to various global arrays
        $_POST    = sanitize($_POST);
        $_GET     = sanitize($_GET);
        $_REQUEST = sanitize($_REQUEST);
        $_COOKIE  = sanitize($_COOKIE);
        if (isset($_SESSION)) {
            $_SESSION = sanitize($_SESSION);
        }
    }

    //Detect malicious patterns in the query string to identify potential SQL injection attacks
    $query_string = $_SERVER['QUERY_STRING'];
    $patterns = array(
        // Add various patterns here used to detect SQL injection attempts
        // ...
    );
    foreach ($patterns as $pattern) {
        if (strpos(strtolower($query_string), strtolower($pattern)) !== false) {
            // If a malicious pattern is found, handle the security measures

            $querya = strip_tags(addslashes($query_string));
            $type   = "SQLi";

            //Logging - Record the detected SQL injection attempt (if enabled)
            if ($settings['sqli_logging'] == 1) {
                psec_logging($mysqli, $type);
            }

            //AutoBan - Automatically ban the source of the detected attack (if enabled)
            if ($settings['sqli_autoban'] == 1) {
                psec_autoban($mysqli, $type);
            }

            //E-Mail Notification - Send a notification email about the detected attack (if enabled)
            if ($settings['mail_notifications'] == 1 && $settings['sqli_mail'] == 1) {
                psec_mail($mysqli, $type);
            }

            //Redirect the user to a predefined URL (specified in $settings['sqli_redirect']) after detecting an attack
            echo '<meta http-equiv="refresh" content="0;url=' . $settings['sqli_redirect'] . '" />';
            exit;
        }
    }
}
?>
