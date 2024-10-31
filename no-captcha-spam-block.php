<?php
/*
Plugin Name: No-captcha Spam Block
Description: Analyzes comments and tries to block any that are spam.
Version: 1.0.0
*/

if (!defined('DB_NAME')) {
    header('HTTP/1.0 403 Forbidden');
    die;
}

define('NCSB_VERSION', '1.0.0');

function ncsb_init_session() {
    if (session_id() == '') {
        session_start();
    }
}

add_action('init', 'ncsb_init_session', 1);

if (!class_exists("NCSB")) {
    class NCSB {

        // Register actions
        public function __construct() {global $wp_version; 
            if ( version_compare($wp_version, '3.4', '<') ) 
                return false; 
    
            add_action( 'init', array( $this, 'init' ) );
        }
        
        function init() {
            add_option('ncsb_threshold', 20, '', 'yes');
            
            add_action('comment_form', array($this, 'pre_comment'));
            add_filter('pre_comment_approved', array($this, 'check_comment'), 10, 2);
        }
        
        // Before the comment form is displayed, prepare the token and session
        function pre_comment($postID) {
            $start = time();
            $token = md5($start.$_SERVER['SERVER_NAME'].$_SERVER['REMOTE_ADDR'].$postID);
            
            if (session_id() != '') {
                $_SESSION['start'] = $start;
                $_SESSION['token'] = $token;
            }
            
            echo '<input type="hidden" name="token" value="'.$token.'">';
        }
        
        // Common functions 1: Get trigrams from a string
        function get_trigrams($word) {
            $trigrams = array();
            $len = strlen($word);
            for($i = 0; $i < $len; $i++) {
                if($i > 1) {
                    $ng = '';
                    for($j = 2; $j >= 0; $j--) {
                        $ng .= $word[$i - $j];
                    }
                    $trigrams[] = $ng;
                }
            }
            return $trigrams;
        }
        
        // Common functions 2: Get a list of URLs in a string
        function get_url_list($comment) {
            $url_regex = '/(https?\:\/\/[\w\-\.\~\!\*\'\(\)\;\:\@\&\=\+\$\,\/\?\%\#\[\]]+)/i';
            $url_list = array();
            
            if (preg_match_all($url_regex, $comment, $matches)) {
                $url_list = $matches[1];
            }

            return $url_list;
        }
        
        // Common functions 3: Get any duplicates in an array
        function get_duplicates($array) {
            return array_unique(array_diff_assoc($array, array_unique($array)));
        }
        
        // Check that the posted token is the same as in the comment form
        function check_token() {
            $score = 0;
            
            $token_post = (isset($_POST['token']) && ctype_alnum($_POST['token'])) ? $_POST['token'] : '';
            $token_session = (isset($_SESSION['token']) && ctype_alnum($_SESSION['token'])) ? $_SESSION['token'] : '';
            
            if (empty($token_post) || !isset($token_session) || $token_post != $token_session) {
                $score = 40;
            }
            
            return $score;
        }
        
        // Check the time from page load to comment posting
        function check_delay() {
            $score = 0;
            
            if (isset($_SESSION['start'])) {
                $end = time();
                $delay = $end - $_SESSION['start'];
                $score = ($delay > 20) ? 0 : 40 - ($delay * 2);
            }
            
            return $score;
        }
        
        // Use trigrams to check similarity of comment and blog post
        function check_similarity($commentdata) {
            global $post;
            $comment = trim($commentdata['comment_content']);
            $score = 0;
            
            $similarity = 1;
            if (strlen($comment) > 3) {
                $postContent = strip_tags($post->post_content);
                $arr_post = $this->get_trigrams($postContent);
                $commentContent = strip_tags($comment);
                $arr_comment = array_unique($this->get_trigrams($commentContent));
                
                $count = 0;
                foreach ($arr_comment as $trigram) {
                    if (in_array($trigram, $arr_post)) {
                        $count++;
                    }
                }
                
                $similarity = $count / count($arr_comment);
            }
            $score = round(($similarity * -100) + 20);
            $score = ($score < 0) ? 0 : $score;
            
            return $score;
        }
        
        // Check if the comment contains the author URL
        function check_author_url($commentdata) {
            $comment = trim($commentdata['comment_content']);
            $score = 0;
            $author_url = rtrim(esc_url_raw($commentdata['comment_author_url']), '/');
            $author_url_parts = parse_url(author_url);
            $author_domain = $author_url_parts['host'];
            
            if (stripos($comment, $author_url) !== false) {
                $score = 10;
            }
            
            return $score;
        }
        
        // Count the number of URLs in the comment, any duplicates and the ratio of URLs to content
        function check_url_count($commentdata) {
            $comment = trim($commentdata['comment_content']);
            $url_list = $this->get_url_list($comment);
            
            $score = count($url_list) * 4;
            
            $dupes = $this->get_duplicates($url_list);
            if (count($dupes) > 0) {
                $score += 10;
            }
            
            $comment_length = strlen($comment);
            $url_length = 0;
            foreach($url_list as $url) {
                $url_length += strlen($url);
            }
            
            if ($url_length == $comment_length) {
                $score = 20;
            } else {
                $url_ratio = $url_length / $comment_length;
                $score += round($url_ratio * 10);
            }
            
            return $score;
        }
        
        // Main comment check function
        function check_comment($approved, $commentdata) {
            // Check for empty comments
            $comment = trim($commentdata['comment_content']);
            if (strlen($comment) < 1) {
                $approved = 'spam';
            } else {
                $threshold = get_option('ncsb_threshold', 20);
                $checks = array();
                
                $checks['token'] = $this->check_token();
                $checks['delay'] = $this->check_delay();
                $checks['similarity'] = $this->check_similarity($commentdata);
                $checks['author_url'] = $this->check_author_url($commentdata);
                $checks['url_count'] = $this->check_url_count($commentdata);
                
                $total_score = array_sum($checks);
                $approved = (array_sum($checks) >= $threshold) ? 'spam' : $approved;
            }
            
            return $approved;
        }

    }
    
    new NCSB();
}
