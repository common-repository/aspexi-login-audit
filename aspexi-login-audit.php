<?php
/*
Plugin Name: Aspexi Login Audit
Plugin URI:  http://aspexi.com/downloads/aspexi-login-audit/?src=premium_plugin
Description: This plugin helps you to keep an audit trail of user login activities such as successful login, logout, failed login and more to ensure your site performance and monitor potential hacker attacks.
Author: Aspexi
Version: 1.0.2
Author URI: http://aspexi.com/
License: GPLv2 or later
*/

defined('ABSPATH') or exit();

if ( !class_exists( 'AspexiLoginAudit' ) ) {

    define('ASPEXILOGINAUDIT_VERSION', '1.0.2');
    define('ASPEXILOGINAUDIT_URL', plugin_dir_url( __FILE__ ) );
    define('ASPEXILOGINAUDIT_ADMIN_URL', 'options-general.php?page=' . basename( __FILE__ ) );

    class AspexiLoginAudit
    {
        const ALA_LOGIN_ANY = 0;
        const ALA_LOGIN_SUCCESS = 1;
        const ALA_LOGIN_ERROR = 2;
        const ALA_LOGOUT = 4;
        const ALA_PASSWORD_RESET = 5;

        static $table_name = 'ala_logs';
        static $cron_tag = 'ala_delete_logs';

        private $config = array();
        private $logs_per_page = 5;
        protected $messages = array();
        protected $errors = array();
        private $statuses = array(
            self::ALA_LOGIN_ANY => array(
                'name' => 'Any',
                'value' => '',
            ),
            self::ALA_LOGIN_SUCCESS => array(
                'name' => 'Login Successful',
                'value' => 'success',
            ),
            self::ALA_LOGIN_ERROR => array(
                'name' => 'Login Failed',
                'value' => 'error',
            ),

            self::ALA_LOGOUT => array(
                'name' => 'Log out',
                'value' => 'logout',
            ),
            self::ALA_PASSWORD_RESET => array(
                'name' => 'Password reset',
                'value' => 'password-reset',
            ),
        );

        public function __construct() {

            $this->settings();

            add_action( 'admin_menu', array( &$this, 'admin_menu' ) );
            add_action( 'wp_login', array( &$this, 'wp_login' ), 10, 2);
            add_action( 'wp_logout', array( &$this, 'wp_logout' ) );
            add_action( 'wp_login_failed', array( &$this, 'wp_login_failed' ) );
            add_action( 'password_reset', array( &$this, 'password_reset' ), 10, 2 );
            add_action( 'admin_enqueue_scripts', array( &$this, 'admin_scripts' ) );
            add_action( 'wp', array( &$this, 'cron' ) );
            add_action( self::$cron_tag, array( &$this, 'delete_logs' ), 10, 1 );

            add_filter( 'plugin_action_links',  array( &$this, 'settings_link' ), 10, 2);

            register_activation_hook( __FILE__, array( &$this, 'db_install' ) );
            register_uninstall_hook( __FILE__, array( 'AspexiLoginAudit', 'uninstall' ) );
            register_deactivation_hook( __FILE__, array( &$this, 'clear_cron' ) );

            load_plugin_textdomain( 'aspexiloginaudit', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
        }

        public function settings() {
            $config_default = array(
                'log_info_type' => 'success|error',
                'logs_days' => '0',
                'logs_per_page' => $this->logs_per_page,
                'remove_data_on_uninstall' => 'on',
            );

            if ( ! get_option( 'aspexiloginaudit_options' ) )
                add_option( 'aspexiloginaudit_options', $config_default, '', 'yes' );

            $this->config = get_option( 'aspexiloginaudit_options' );
        }

        public function admin_menu() {

            add_submenu_page( 'options-general.php', __( 'Aspexi Login Audit', 'aspexiloginaudit' ), __( 'Aspexi Login Audit', 'aspexiloginaudit' ), 'manage_options', basename(__FILE__), array( &$this, 'admin_page' ) );
        }

        public function admin_scripts() {

            if ( isset( $_REQUEST['page'] ) && basename(__FILE__) == $_REQUEST['page'] ) {

                wp_enqueue_style('aspexi-login-audit-admin', ASPEXILOGINAUDIT_URL . '/aspexi-login-audit.css');

                wp_enqueue_style( 'wp-jquery-ui-dialog' );

                wp_enqueue_script( 'aspexi-login-audit-admin', ASPEXILOGINAUDIT_URL . '/js/aspexi-login-audit-admin.js', array( 'jquery', 'jquery-ui-dialog', 'jquery-ui-tooltip' ) );

                wp_localize_script( 'aspexi-login-audit-admin', 'ala', array(
                    'pro_url' => $this->get_pro_url(),
                ) );
            }
        }

        public function admin_page() {

            if ( !current_user_can( 'manage_options' ) )
                wp_die( __( 'You do not have sufficient permissions to access this page.' ) );

            if ( isset( $_REQUEST['ala_form_submit'] ) && check_admin_referer( plugin_basename(__FILE__), 'ala_nonce_name' ) ) {
                if( ! (int)$_REQUEST['ala_logs_days'] < 0 )
                    $this->add_error( __( 'Missing Keep logs for days. Settings not saved.', 'aspexiloginaudit' ) );

                if (!$this->has_errors()) {
                    $ala_request_options = array();

                    $logStatuses = array();
                    foreach ($this->statuses as $key => $status) {
                        if ($key == 0) continue;
                        if (isset($_REQUEST['ala_log_info_type_' . $status['value']]))
                            $logStatuses[] = sanitize_text_field($_REQUEST['ala_log_info_type_' . $status['value']]);
                    }
                    $ala_request_options['log_info_type'] = implode('|', $logStatuses);

                    $ala_request_options['logs_days'] = isset( $_REQUEST['ala_logs_days'] ) ? absint( $_REQUEST['ala_logs_days'] ) : 0;

                    $ala_request_options['remove_data_on_uninstall'] = isset( $_REQUEST['ala_remove_data_on_uninstall'] ) ? sanitize_key( $_REQUEST['ala_remove_data_on_uninstall'] ) : '';

                    $_logs_days = absint( $this->config['logs_days'] );

                    $this->config = array_merge($this->config, $ala_request_options);
                    update_option('aspexiloginaudit_options', $this->config, 'yes');

                    // Clear logs if needed
                    if( $ala_request_options['logs_days'] > 0 && $_logs_days != $ala_request_options['logs_days'] )
                        $this->delete_logs(true);

                    $this->add_message(__('Settings saved.', 'aspexiloginaudit'));
                }
            }

            $_page = 1;

            if ( isset( $_REQUEST['ala_filter_submit'] ) && check_admin_referer( plugin_basename(__FILE__), 'ala_nonce_name' ) ) {
                if ( isset( $_REQUEST['ala_delete_logs'] ) )
                    $this->delete_logs();

                $_filters = array();

                if( isset( $_REQUEST['ala_filter_status'] ) )
                    foreach ($this->statuses as $key => $status)
                        if ( $_REQUEST['ala_filter_status'] == $status['value'])
                            $_filters['status'] = $key;

                if (isset($_GET['ala_page']) && $_GET['ala_page'] > 0) {
                    $_page = absint($_GET['ala_page']);
                } elseif (isset($_POST['ala_page']) && $_POST['ala_page'] > 0) {
                    $_page = absint($_POST['ala_page']);
                } else {
                    $_page = 1;
                }

                $_count = $this->get_logs( array_merge( (array) $_filters, array( 'count_only' => 'yes' ) ) );
                $_max_pages = ceil( $_count / $this->get_logs_per_page() );

                if( $_page > $_max_pages )
                    $_page = $_max_pages;

                $_filters['page'] = $_page;

                if( isset( $_REQUEST['ala_logs_per_page'] ) && (int) $_REQUEST['ala_logs_per_page'] > 0 ) {
                    $this->config['logs_per_page'] = (int) $_REQUEST['ala_logs_per_page'];
                    update_option('aspexiloginaudit_options', $this->config, 'yes');
                }
            }

            ?>
            <div id="dialog-block" class="none">
                <p><?php echo __( 'IP blocking is available in PRO version only. Would you like to see more details?', 'aspexiloginaudit' ); ?></p>
            </div>
            <div id="dialog-export" class="none">
                <p><?php echo __( 'Exporting to CSV is available in PRO version only. Would you like to see more details?', 'aspexiloginaudit'); ?></p>
            </div>
            <div class="wrap">
                <h1><?php _e( 'Aspexi Login Audit Settings', 'aspexiloginaudit' ); ?></h1>
                <h2 class="nav-tab-wrapper">
                    <a class="nav-tab <?php echo ( $_REQUEST['logs'] != 'true' && $_REQUEST['support'] != 'true' && $_REQUEST['email'] != 'true' ) ? 'nav-tab-active' : ''; ?>" href="options-general.php?page=<?php echo dirname( plugin_basename( __FILE__ ) ).'.php'; ?>"><?php _e( 'Settings', 'aspexiloginaudit' ); ?></a>
                    <a class="nav-tab <?php echo ($_REQUEST['email'] == 'true') ? 'nav-tab-active' : ''; ?>" href="options-general.php?page=<?php echo dirname( plugin_basename( __FILE__ ) ).'.php'; ?>&email=true"><?php _e( 'Email notifications', 'aspexiloginaudit' ); ?></a>
                    <a class="nav-tab <?php echo ($_REQUEST['logs'] == 'true') ? 'nav-tab-active' : ''; ?>" href="options-general.php?page=<?php echo dirname( plugin_basename( __FILE__ ) ).'.php'; ?>&logs=true"><?php _e( 'Logs', 'aspexiloginaudit' ); ?></a>
                    <a class="nav-tab <?php echo ($_REQUEST['support'] == 'true') ? 'nav-tab-active' : ''; ?>" href="options-general.php?page=<?php echo dirname( plugin_basename( __FILE__ ) ).'.php'; ?>&support=true"><?php _e( 'Support', 'aspexiloginaudit' ); ?></a>
                </h2>
                <div id="poststuff" class="metabox-holder">
                    <div id="post-body">
                        <div id="post-body-content"></div>
                        <?php if ($_REQUEST['logs'] != 'true' && $_REQUEST['support'] != 'true' && $_REQUEST['email'] != 'true'): ?>
                            <form method="post" action="<?php echo ASPEXILOGINAUDIT_ADMIN_URL; ?>">
                                <div class="postbox">
                                    <div class="inside">
                                        <table class="form-table">
                                            <tbody>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Log information type', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <?php $checked = explode( '|', $this->config['log_info_type'] ); ?>
                                                    <?php foreach ($this->statuses as $key => $status): ?>
                                                        <?php if ( $key == self::ALA_LOGIN_ANY ) continue; ?>
                                                        <input type="checkbox" name="ala_log_info_type_<?php echo $status['value']; ?>" <?php echo ( in_array( $status['value'], $checked ) ) ? 'checked' : ''; ?> value="<?php echo $status['value']; ?>"><?php echo __( $status['name'], 'aspexiloginaudit' ); ?><br>
                                                    <?php endforeach; ?>
                                                    <input type="checkbox" disabled readonly><?php echo __( 'Login Failed (Brute Force)', 'aspexiloginaudit' ); ?>&nbsp;<span class="dashicons-tooltip" data-info="Log for example login requests without specific username and password (potential Brute Force attack)."><span class="dashicons dashicons-info"></span></span><br>
                                                    <input type="checkbox" disabled readonly><?php echo __( 'User registration', 'aspexiloginaudit' ); ?>&nbsp;<span class="dashicons-tooltip" data-info="Log user registrations."><span class="dashicons dashicons-info"></span></span><br>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Keep logs for', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input type="text" name="ala_logs_days" size="4" value="<?php echo esc_html( $this->config['logs_days'] ); ?>">&nbsp;<?php _e( 'days (set 0 to keep all logs)', 'aspexiloginaudit' ); ?>
                                                    <span class="dashicons-tooltip" data-info="When set old logs will be automatically deleted."><span class="dashicons dashicons-info"></span></span>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Remove all data on plugin uninstall', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input type="checkbox" name="ala_remove_data_on_uninstall" <?php echo (esc_html( $this->config['remove_data_on_uninstall'] ) == 'on') ? 'checked' : ''; ?> value="on">
                                                </td>
                                            </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <input type="hidden" name="ala_form_submit" value="submit">
                                <?php wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ); ?>
                                <p><input class="button-primary" type="submit" name="send" value="<?php _e('Save settings', 'aspexiloginaudit'); ?>" id="submitbutton" />
                            </form>
                        <?php elseif ( $_REQUEST['email'] == 'true' ): ?>
                            <form method="post" action="<?php echo ASPEXILOGINAUDIT_ADMIN_URL; ?>&email=true">
                                <div class="postbox">
                                    <div class="inside">
                                        <table class="form-table">
                                            <tbody>
                                            <tr valign="top">
                                                <th scope="row"><?php _e( 'Send email to the site admin', 'aspexiloginaudit' ); ?> (<?php echo get_bloginfo( 'admin_email' ); ?>)</th>
                                                <td>
                                                    <input type="checkbox" value="on" name="ala_email_to_admin" disabled readonly />
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Send notification email to the user who is logging in', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input type="checkbox" value="on" name="ala_email_to_user" <?php echo ( $this->config['email_to_user'] == 'on' ) ? 'checked' : '' ; ?> disabled readonly /><br><br>
                                                    <p><?php echo __( 'Notify user if role is', 'aspexiloginaudit' ); ?>:</p><br>
                                                    <?php $configRoles = explode(' ', $this->config['email_to_user_role_list']); ?>
                                                    <?php foreach (get_editable_roles() as $roleId => $role): ?>
                                                        <input disabled readonly type="checkbox" value="<?php echo $roleId; ?>" name="ala_email_to_user_role_<?php echo $roleId; ?>" <?php echo ( in_array( $roleId, $configRoles ) ) ? 'checked' : '' ; ?> /><?php echo $role['name']; ?><br>
                                                    <?php endforeach; ?>
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Send email to (one email per line)', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input disabled readonly type="checkbox" value="on" name="ala_email_to" <?php echo ( $this->config['email_to'] == 'on' ) ? 'checked' : '' ; ?> /><br><br>
                                                    <textarea disabled readonly name="ala_email_to_list" cols="30" rows="10"><?php echo str_replace(array(' ', ','), array('', "\n"), $this->config['email_to_list']); ?></textarea><br>
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Send email information type', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_success" value="on"><?php _e('Login Successful','aspexiloginaudit'); ?><br />
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_error" value="on"><?php _e('Login Failed','aspexiloginaudit'); ?><br />
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_bruteforce" value="on" ><?php _e('Login Failed (Brute Force)','aspexiloginaudit'); ?><br />
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_bruteforce2" value="on" ><?php _e('Log out','aspexiloginaudit'); ?><br />
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_bruteforce3" value="on" ><?php _e('Password reset','aspexiloginaudit'); ?><br />
                                                    <input disabled readonly type="checkbox" name="ala_email_info_type_bruteforce4" value="on" ><?php _e('User registration','aspexiloginaudit'); ?><br />
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Success email', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <p><?php echo __( 'Title', 'aspexiloginaudit' ); ?><br><input disabled readonly type="text" name="ala_email_success_title" size="50" value="Login of the user: {username} on website: {website}"><br><?php _e( 'Available variables', 'aspexiloginaudit' ); ?>: {username}, {website}<br><br></p>
                                                    <p><?php echo __( 'Content', 'aspexiloginaudit' ); ?><br><textarea disabled readonly name="ala_email_success_content" id="" cols="50" rows="10">Hello, a user has logged in on the website. Here are the details of this access:<?php echo "\n"; ?>User: {username}<?php echo "\n"; ?>User email: {useremail}<?php echo "\n"; ?>Date: {date}<?php echo "\n"; ?>IP: {ip}<?php echo "\n"; ?>User agent: {useragent}<?php echo "\n"; ?>Http referer: {httpreferer}</textarea><br><?php _e( 'Available variables', 'aspexiloginaudit' ); ?>: {username}, {useremail}, {date}, {ip}, {useragent}, {httpreferer}<br><br></p>
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Error email', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <p><?php echo __( 'Title', 'aspexiloginaudit' ); ?><br><input disabled readonly type="text" name="ala_email_error_title" size="50" value="Error login of the username: {username} on website: {website}"><br><?php _e( 'Available variables', 'aspexiloginaudit' ); ?>: {username}, {website}<br><br></p>
                                                    <p><?php echo __( 'Content', 'aspexiloginaudit' ); ?><br><textarea disabled readonly name="ala_email_error_content" id="" cols="50" rows="10">Hello, someone just failed to log in on website. Here are the details of this access:<?php echo "\n"; ?>User: {username}<?php echo "\n"; ?>User email: {useremail}<?php echo "\n"; ?>Date: {date}<?php echo "\n"; ?>IP: {ip}<?php echo "\n"; ?>User agent: {useragent}<?php echo "\n"; ?>Http referer: {httpreferer}</textarea><br><?php _e( 'Available variables', 'aspexiloginaudit' ); ?>: {username}, {useremail}, {date}, {ip}, {useragent}, {httpreferer}<br><br></p>
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            <tr valign="top">
                                                <th scope="row"><?php _e('Email limit per hour', 'aspexiloginaudit'); ?></th>
                                                <td>
                                                    <input type="text" name="ala_email_limit_count" disabled readonly size="4" value="20"><br>
                                                    <?php echo $this->get_pro_link(); ?>
                                                </td>
                                            </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <input type="hidden" name="ala_form_submit" value="submit">
                                <?php wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ); ?>
                                <p><input class="button-primary" type="submit" name="send" value="<?php _e('Save settings', 'aspexiloginaudit'); ?>" id="submitbutton" />
                            </form>
                        <?php elseif ( $_REQUEST['support'] == 'true' ): ?>
                            <div class="postbox">
                                <div class="inside"><?php echo __( 'Any support queries or comments please send to', 'aspexiloginaudit' ); ?>&nbsp;<a href="mailto:support@aspexi.com">support@aspexi.com</a></div>
                            </div>
                        <?php elseif ( $_REQUEST['logs'] == 'true' ) : ?>
                        <?php
                        if( isset( $_filters ) )
                            $filters = &$_filters;
                        else
                            $filters = array();
                        ?>
                        <form method="post" action="<?php echo ASPEXILOGINAUDIT_ADMIN_URL; ?>&logs=true" autocomplete="off" style="display: inline-block;">
                            <input type="hidden" name="ala_filter_submit" value="submit">
                            <?php wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ); ?>
                            <b><?php _e( 'Status', 'aspexiloginaudit' ); ?>:</b>
                            <select name="ala_filter_status">
                                <?php foreach ( $this->statuses as $key => $status ): ?>
                                    <option value="<?php echo $status['value']; ?>" <?php echo ( isset( $filters['status'] ) && $key == $filters['status'] ) ? 'selected' : ''; ?>><?php echo __( $status['name'], 'aspexiloginaudit' ); ?></option>
                                <?php endforeach; ?>
                                <option value="bruteforce" disabled>Login Failed (Brute Force) - Get PRO version</option>
                                <option value="bruteforce" disabled>User registration - Get PRO version</option>
                            </select>
                            &nbsp;&nbsp; <b><?php _e( 'User', 'aspexiloginaudit' ); ?>:</b>&nbsp;<select name="ala_filter_user">
                                <option value="" disabled selected><?php echo __( 'Any', 'aspexiloginaudit' ); ?></option>
                                <?php
                                $loginInfo = unserialize(get_option('aspexiloginaudit_login_info'));
                                $loginInfo = $this->get_logs( $filters );
                                $users = array();
                                $months = array();
                                foreach ($loginInfo as $log) {
                                    $users[$log->user] = $log->user;

                                    $months[date('m-Y')] = date('F Y');
                                }

                                foreach ($users as $user)
                                    echo '<option value="" disabled>'.$user.'</option>';
                                ?>
                            </select>&nbsp;<?php _e( 'or', 'aspexiloginaudit' ); ?>&nbsp;<input type="text" size="10" name="ala_filter_user_name" value="" disabled readonly>&nbsp;&nbsp; <b>IP:</b>&nbsp;<input type="text" size="10" name="ala_filter_ip" value="" disabled readonly>&nbsp;&nbsp; <select name="ala_filter_ip_type"><option value="" disabled selected><?php echo __( 'Any', 'aspexiloginaudit' ); ?></option><option value="blocked" disabled><?php echo __( 'Blocked', 'aspexiloginaudit' ); ?></option><option value="not_blocked" disabled><?php _e( 'Not Blocked', 'aspexiloginaudit' ); ?></option></select>&nbsp;&nbsp; <b><?php _e( 'Date', 'aspexiloginaudit' ); ?>:</b>&nbsp;<select name="ala_filter_date">
                                <option value="" disabled selected><?php echo __( 'Any', 'aspexiloginaudit' ); ?></option>
                                <?php
                                foreach ($months as $month)
                                    echo '<option value="" disabled>'.$month.'</option>';
                                ?>
                            </select>&nbsp;&nbsp; <b><?php _e( 'Data', 'aspexiloginaudit' ); ?>:</b>&nbsp;<select name="ala_filter_data">
                                <option value="" disabled selected><?php echo __( 'Any', 'aspexiloginaudit' ); ?></option>
                                <option value="status" disabled><?php echo __( 'Aggregate by Status', 'aspexiloginaudit' ); ?></option>
                                <option value="username" disabled><?php echo __( 'Aggregate by User Name', 'aspexiloginaudit' ); ?></option>
                                <option value="userid" disabled><?php echo __( 'Aggregate by User ID', 'aspexiloginaudit' ); ?></option>
                                <option value="useremail" disabled><?php echo __( 'Aggregate by User Email', 'aspexiloginaudit' ); ?></option>
                                <option value="ip" disabled><?php echo __( 'Aggregate by IP', 'aspexiloginaudit' ); ?></option>
                            </select>&nbsp;&nbsp; <input type="Submit" value="<?php _e( 'Filter', 'aspexiloginaudit' ); ?>" class="button-primary" style="vertical-align: middle;" />
                    </div>
                    </form>
                    <br><br>
                    <?php

                    $loginInfo = $this->get_logs( $filters );

                    if ($loginInfo != false): ?>
                        <table id="ala_logs" class="wp-list-table widefat fixed striped">
                            <thead>
                            <tr>
                                <th scope="col" class="manage-column"><?php echo __('Status', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User email', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('IP', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User agent', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('HTTP Referer', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('Date', 'aspexiloginaudit') ;?></th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php

                            $request_status = '';
                            if (isset($_POST['ala_filter_status'])) {
                                $request_status_foreach = $_POST['ala_filter_status'];
                                foreach ($this->statuses as $status)
                                    if ($status['value'] == $request_status_foreach)
                                        $request_status = $status['value'];
                            }

                            if (!empty($request_status)) {
                                $logs = array();
                                foreach ($loginInfo as $log) {
                                    if ($log->status == $request_status)
                                        $logs[] = $log;
                                }
                            }
                            ?>
                            <?php foreach( $loginInfo as $logs):
                            $log_status = 0;
                            $tr_color = '';
                            switch ($logs->status) {
                                case self::ALA_LOGIN_SUCCESS:
                                    $log_status = 'Login Successful';
                                    $tr_color = 'background-color: rgba(0, 255, 0, 0.05);';
                                    break;
                                case self::ALA_LOGIN_ERROR:
                                    $log_status = 'Login Failed';
                                    $tr_color = 'background-color: rgba(255, 0, 0, 0.05);';
                                    break;
                                case self::ALA_LOGOUT:
                                    $log_status = 'Log out';
                                    $tr_color = 'background-color: rgba(0, 0, 255, 0.05);';
                                    break;
                                case self::ALA_PASSWORD_RESET:
                                    $log_status = 'Password reset';
                                    $tr_color = 'background-color: rgba(126, 0, 126, 0.05);';
                                    break;
                            }
                            ?>
                                <tr style="<?php echo $tr_color; ?>">
                                    <td data-colname="<?php echo __( 'Status', 'aspexiloginaudit' ); ?>"><?php echo __( $log_status, 'aspexiloginaudit' ); ?></td>
                                    <td data-colname="<?php echo __( 'User', 'aspexiloginaudit' ); ?>"><?php echo get_avatar($logs->user_email, 45).'<div style="padding-left: 50px; display: block;">'.$logs->user.'<br><span>' . (0 != $logs->user_id ? implode(', ', get_userdata($logs->user_id)->roles) : '') . '</span>'; ?></div></td>
                                    <td data-colname="<?php echo __( 'User email', 'aspexiloginaudit' ); ?>"><?php echo ( ! strlen( $logs->user_email ) ? __( 'Unknown', 'aspexiloginaudit' ) : '<a href="mailto:'. $logs->user_email . '">' . $logs->user_email . '</a>' ); ?></td>
                                    <td data-colname="<?php echo __( 'IP', 'aspexiloginaudit' ); ?>"><?php ( $this->get_ip_url( $logs->ip || $this->get_ip() != $logs->ip ) ? 'block' : '' ) ?> <button class="button-secondary block">Block</button>&nbsp; <?php echo ( $logs->ip == 'unknown' ) ? __( 'Unknown', 'aspexiloginaudit' ) : $logs->ip ; ?></td>
                                    <td data-colname="<?php echo __( 'HTTP Referer', 'aspexiloginaudit' ); ?>"><?php echo $logs->referer; ?>&nbsp;</td>
                                    <td data-colname="<?php echo __( 'User agent', 'aspexiloginaudit' ); ?>"><?php echo $logs->user_agent; ?>&nbsp;</td>
                                    <td data-colname="<?php echo __( 'Date', 'aspexiloginaudit' ); ?>"><?php echo date('Y-m-d H:i:s', strtotime($logs->date . ' ' . get_option('gmt_offset') . ' hours')); ?>&nbsp;</td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                            <tfoot>
                            <tr>
                                <td colspan="7"><?php echo $this->get_pro_link(); ?></td>
                            </tr>
                            </tfoot>
                        </table>
                        <br>
                        <button style="float: left; margin-right: 10px" type="button" class="button-primary export"><?php echo __( 'Export to CSV', 'aspexiloginaudit' ); ?></button>
                        <?php echo $this->get_delete_logs_button($filters); ?>
                        <?php echo $this->get_logs_per_page_filter( $filters ); ?>
                        <?php echo $this->get_pagination($this->get_logs( array_merge( (array) $filters, array( 'count_only' => 'yes' ) ) ), $_page, $filters); ?>
                        <div class="clear"></div>
                        <br>
                    <?php else : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                            <tr>
                                <th scope="col" class="manage-column"><?php echo __('Status', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User email', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('IP', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('User agent', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('HTTP Referer', 'aspexiloginaudit') ;?></th>
                                <th scope="col" class="manage-column"><?php echo __('Date', 'aspexiloginaudit') ;?></th>
                            </tr>
                            </thead>
                            <tbody>
                            <tr>
                                <td colspan="7"><?php echo __( 'No data available yet.', 'aspexiloginaudit' ); ?></td>
                            </tr>
                            </tbody>
                        </table>
                        <br>
                        <button style="float: left; margin-right: 10px" type="button" class="button-primary export"><?php echo __( 'Export to CSV', 'aspexiloginaudit' ); ?></button>
                        <?php echo $this->get_delete_logs_button($filters); ?>
                        <?php echo $this->get_logs_per_page_filter( $filters ); ?>
                        <?php echo $this->get_pagination($this->get_logs( array_merge( (array) $filters, array( 'count_only' => 'yes' ) ) ), $_page, $filters); ?>
                        <div class="clear"></div>
                    <?php endif; ?>
                    <?php endif; ?>
                    <br>
                    <div class="postbox">
                        <h3><span>Made by</span></h3>
                        <div class="inside">
                            <div style="width: 170px; margin: 0 auto;">
                                <a href="<?php echo $this->get_pro_url(); ?>" target="_blank"><img src="<?php echo ASPEXILOGINAUDIT_URL.'images/aspexi300.png'; ?>" alt="" border="0" width="150" /></a>
                            </div>
                        </div>
                    </div>
                    <div class="postbox">
                        <h3><span><?php _e('Security Services with ASecure.me', 'aspexiloginaudit'); ?></span></h3>
                        <div class="inside">
                            <div style="width: 170px; margin: 0 auto;">
                                <a href="https://asecure.me/?utm_source=loginfree" target="_blank"><img src="<?php echo ASPEXILOGINAUDIT_URL.'images/be250.png'; ?>" alt="" border="0" width="170" /></a>
                            </div>
                            <p style="text-align: center;"><?php _e('We offer security services, backups and more. <a href="https://asecure.me/?utm_source=loginfree" target="_blank">Check out now</a>.'); ?></p>
                        </div>
                    </div>
                    <div id="aspexifblikebox-footer" style="text-align:left;text-shadow:0 1px 0 #fff;margin:0 0 10px;color:#888;"><?php echo sprintf(__('If you like %s please leave us a %s rating. A huge thank you in advance!'), '<strong>Aspexi Login Audit</strong>', '<a href="https://wordpress.org/plugins/aspexi-login-audit/reviews/#new-post" target="_blank">&#9733;&#9733;&#9733;&#9733;&#9733</a>') ?></div>
                    <script type="text/javascript">
                        jQuery(document).ready(function(){
                            jQuery('#wpfooter').prepend( jQuery('#aspexifblikebox-footer') );
                        });
                    </script>
                </div>
            </div>
            <?php
        }

        public function get_pagination( $count, $page, $filters = array() ) {

            $ret = '';

            $url = ASPEXILOGINAUDIT_ADMIN_URL.'&logs=true';

            $_max_pages = ceil( $count / $this->config['logs_per_page'] );

            $filters_hidden = $this->get_filters_hidden( $filters );

            $prev = '<form method="post" action="'.$url.'&ala_page='.( $page - 1 ).'" style="display: inline-block; vertical-align: middle;" autocomplete="off">
                            <input type="hidden" name="ala_filter_submit" value="submit">'.$filters_hidden.'
                            '.wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ).'
                            <div><input type="Submit" value="' . __( 'Previous', 'aspexiloginaudit' ) . '" class="button-secondary" /></div>
                        </form>';

            $next = '<form method="post" action="'.$url.'&ala_page='.( $page + 1 ).'" style="display: inline-block; vertical-align: middle;" autocomplete="off">
                            <input type="hidden" name="ala_filter_submit" value="submit">'.$filters_hidden.'
                            '.wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ).'
                            <div><input type="Submit" value="' . __( 'Next', 'aspexiloginaudit' ) . '" class="button-secondary" /></div>
                        </form>';

            $page_info = '<form method="post" action="'.$url.'" style="display: inline-block; vertical-align: middle;" autocomplete="off">
                            <input type="hidden" name="ala_filter_submit" value="submit">'.$filters_hidden.'
                            <input type="text" name="ala_page" value="'.$page.'" size="1">
                            '.wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ).'</form> / '.$_max_pages;

            if( $page > 1 ) {
                if( $page < $_max_pages )
                    $ret .= $prev.'&nbsp;&nbsp;&nbsp;'.$page_info.'&nbsp;&nbsp;&nbsp;'.$next;
                else
                    $ret .= $prev.'&nbsp;&nbsp;&nbsp;'.$page_info;
            } else {
                if( $page < $_max_pages )
                    $ret .= $page_info.'&nbsp;&nbsp;&nbsp;'.$next;
            }

            $ret = '<div style="float: right; vertical-align: middle;">'.$ret.'</div>';

            return $ret;
        }

        public function get_logs( $filters = array(), $no_limit = false )
        {
            global $wpdb;

            $_where = '';
            $extra = '';
            $_select = '*';

            if( isset( $filters['status'] ) && $filters['status'] != self::ALA_LOGIN_ANY ) {

                $_where = ' AND status = ' . $filters['status'];
            }

            if( strlen( $_where ) )
                $extra .= "WHERE hidden=0".$_where;
            else
                $extra .= "WHERE hidden=0";

            $offset = '';
            if( isset( $filters['page'] ) && $filters['page'] > 1 )
                $offset = $wpdb->prepare( ' OFFSET %d', (int) ( ( $filters['page']-1 ) * $this->get_logs_per_page() ) );

            $limit = $no_limit ? '' : ' LIMIT '.$wpdb->prepare( '%d', $this->get_logs_per_page() ).$offset;

            $sql = 'SELECT * FROM ' . $wpdb->prefix . self::$table_name . ' ' . $extra  . ' ORDER BY date DESC';

            $sql_final = 'SELECT '.$_select.' FROM ' . $wpdb->prefix . self::$table_name . ' ' . $extra  . ' ORDER BY date DESC'.$limit;

            if( isset( $filters['count_only'] ) && 'yes' == $filters['count_only'] ) {

                $sql = str_replace( '*', 'COUNT(*)', $sql );

                return $wpdb->get_var( $sql );
            }
            else
                return $wpdb->get_results( $sql_final );
        }

        public function get_filters_hidden( $filters ) {

            $_status_input = '';

            if( isset( $filters['status'] ) )
                $_status_input = '<input type="hidden" name="ala_filter_status" value="'.$this->statuses[absint( $filters['status'] )]['value'].'">';

            return  $_status_input;
        }

        public function get_pro_url() {

            return 'http://aspexi.com/downloads/aspexi-login-audit/?src=free_plugin';
        }

        public function get_pro_link() {

            return '<a href="'.$this->get_pro_url().'" target="_blank">'.__( 'Get PRO version', 'aspexiloginaudit' ).'</a>';
        }

        public function settings_link( $action_links, $plugin_file ) {

            if( $plugin_file == plugin_basename(__FILE__) ) {
                $pro_link = $this->get_pro_link();
                array_unshift( $action_links, $pro_link );

                $settings_link = '<a href="options-general.php?page=' . basename( __FILE__ )  .  '">' . __("Settings") . '</a>';
                array_unshift( $action_links, $settings_link );

            }
            return $action_links;
        }

        public function wp_login( $user_login, WP_User $user ) {

            $logInfoTypes = explode( '|',  $this->config['log_info_type'] );
            if( in_array( 'success', $logInfoTypes ) )
                $hidden = 0;
            else
                $hidden = 1;

            global $wpdb;

            $wpdb->insert($wpdb->prefix . self::$table_name, array(
                'status' => self::ALA_LOGIN_SUCCESS,
                'user' => $user->user_login,
                'user_id' => $user->ID,
                'user_email' => $user->user_email,
                'ip' => $this->get_ip(),
                'user_agent' => $this->get_user_agent(),
                'referer' => $this->get_referer(),
                'date' => date('Y-m-d H:i:s'),
                'email_sent' => '0',
                'hidden' => $hidden
            ));
        }

        public function wp_logout()
        {
            $user = wp_get_current_user();

            $logInfoTypes = explode( '|',  $this->config['log_info_type'] );
            if( in_array( 'logout', $logInfoTypes ) )
                $hidden = 0;
            else
                $hidden = 1;

            global $wpdb;
            $wpdb->insert($wpdb->prefix . self::$table_name, array(
                'status' => self::ALA_LOGOUT,
                'user' => $user->user_login,
                'user_id' => $user->ID,
                'user_email' => $user->user_email,
                'ip' => $this->get_ip(),
                'user_agent' => $this->get_user_agent(),
                'referer' => $this->get_referer(),
                'date' => date('Y-m-d H:i:s'),
                'email_sent' => '0',
                'hidden' => $hidden
            ));
        }

        public function password_reset($user, $new_pass)
        {
            $logInfoTypes = explode( '|',  $this->config['log_info_type'] );
            if( in_array( 'password-reset', $logInfoTypes ) )
                $hidden = 0;
            else
                $hidden = 1;

            global $wpdb;
            $wpdb->insert($wpdb->prefix . self::$table_name, array(
                'status' => self::ALA_PASSWORD_RESET,
                'user' => $user->user_login,
                'user_id' => $user->ID,
                'user_email' => $user->user_email,
                'ip' => $this->get_ip(),
                'user_agent' => $this->get_user_agent(),
                'referer' => $this->get_referer(),
                'date' => date('Y-m-d H:i:s'),
                'email_sent' => '0',
                'hidden' => $hidden
            ));
        }

        public function wp_login_failed($username) {

            $user_email = '';
            $user = get_user_by('login', $username);
            if ($user != false)
                $user_email = $user->user_email;

            $logInfoTypes = explode( '|',  $this->config['log_info_type'] );
            if( in_array( 'error', $logInfoTypes ) )
                $hidden = 0;
            else
                $hidden = 1;

            global $wpdb;

            $wpdb->insert( $wpdb->prefix . self::$table_name, array(
                'status' => self::ALA_LOGIN_ERROR,
                'user' => $username,
                'user_id' => $user != false ? $user->ID : '',
                'user_email' => $user != false ? $user->user_email : '',
                'ip' => $this->get_ip(),
                'user_agent' => $this->get_user_agent(),
                'referer' => $this->get_referer(),
                'date' => date('Y-m-d H:i:s'),
                'email_sent' => '0',
                'hidden' => $hidden
            ));
        }

        public function get_ip_url( $ip ) {

            if( $ip && false === !filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) )

                return 'http://www.ip-adress.com/ip_tracer/'.$ip;
            else

                return false;
        }

        public function get_ip() {

            $indices = array(
                'HTTP_CF_CONNECTING_IP',
                'HTTP_CLIENT_IP',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED',
                'HTTP_X_CLUSTER_CLIENT_IP',
                'HTTP_FORWARDED_FOR',
                'HTTP_FORWARDED',
                'HTTP_VIA',
                'REMOTE_ADDR'
            );

            foreach ( $indices as $index ) {

                if ( empty( $_SERVER[$index] ) ) {
                    continue;
                }

                $ip = filter_var( $_SERVER[$index], FILTER_VALIDATE_IP );

                if ( ! empty( $ip ) ) {
                    break;
                }
            }

            $ip = esc_sql( (string) $ip );

            return strlen( $ip ) ? $ip : 'unknown';
        }

        public function get_user_agent() {

            return ( isset( $_SERVER['HTTP_USER_AGENT'] ) ? esc_html( $_SERVER['HTTP_USER_AGENT'] ) : '' );
        }

        public function get_referer() {

            return ( isset( $_SERVER['HTTP_REFERER'] ) ? esc_html( $_SERVER['HTTP_REFERER'] ) : '' );
        }

        public function uninstall() {

            global $wpdb;

            $options = get_option( 'aspexiloginaudit_options' );
            if ($options['remove_data_on_uninstall'] == 'on') {
                if ( is_multisite() ) {
                    $blog_ids = $wpdb->get_col( "SELECT blog_id FROM $wpdb->blogs" );
                    $original_blog_id = get_current_blog_id();
                    foreach ( $blog_ids as $blog_id ) {
                        switch_to_blog( $blog_id );
                        $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::$table_name );
                    }
                    switch_to_blog( $original_blog_id );
                } else {
                    $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::$table_name );
                }
            }

            delete_option('aspexiloginaudit_options');
            wp_clear_scheduled_hook( self::$cron_tag );
        }

        protected function add_message( $message ) {

            $message = trim( $message );

            if( strlen( $message ) )
                $this->messages[] = $message;
        }

        protected function add_error( $error ) {
            $error = trim( $error );

            if( strlen( $error ) )
                $this->errors[] = $error;
        }

        public function has_errors() {
            return count( $this->errors );
        }

        public function display_admin_notices( $echo = false ) {

            $ret = '';

            foreach( (array)$this->errors as $error ) {
                $ret .= '<div class="error fade"><p><strong>'.$error.'</strong></p></div>';
            }

            foreach( (array)$this->messages as $message ) {
                $ret .= '<div class="updated fade"><p><strong>'.$message.'</strong></p></div>';
            }

            if( $echo )
                echo $ret;
            else
                return $ret;
        }

        public function delete_logs($cron = false) {
            global $wpdb;

            if( $cron ) {

                $logs_days = (int)$this->config['logs_days'];

                if( 0 < $logs_days )
                    return $wpdb->query( 'DELETE FROM ' . $wpdb->prefix . self::$table_name . ' WHERE date < "' . date_i18n('Y-m-d H:i:s') . '" - INTERVAL ' . $logs_days . ' DAY');
            } else

                return $wpdb->query( 'DELETE FROM ' . $wpdb->prefix . self::$table_name );
        }

        public function cron() {

            $logs_days = (int) $this->config['logs_days'];

            $next_timestamp = wp_next_scheduled( self::$cron_tag, array( true ) );

            // Check if we should ever initiate WP cron
            if( 0 < $logs_days && ! $next_timestamp ) {

                // hourly, twicedaily, daily available only
                wp_schedule_event( time(), 'daily', self::$cron_tag, array( true ) );

            } else if ( 0 == $logs_days || ! $logs_days ) {

                // if next scheduled exists - remove it
                if( $next_timestamp ) {

                    wp_unschedule_event( $next_timestamp, self::$cron_tag, array( true ) );
                }
            }
        }

        public function clear_cron() {

            wp_clear_scheduled_hook( self::$cron_tag );
        }

        public function get_delete_logs_button( $filters = array() ) {

            $ret = '';

            $url = ASPEXILOGINAUDIT_ADMIN_URL.'&logs=true';

            $filters_hidden = $this->get_filters_hidden( $filters );

            $form = '<form method="post" action="' . $url . '" style="display: inline-block;" autocomplete="off">
                        <input type="hidden" name="ala_filter_submit" value="submit">'.$filters_hidden.'
                        '.wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ).'
                        <div><input onclick="return confirm(\'' . __( 'IMPORTANT: All Aspexi Login Audit users stats records will be deleted', 'aspexiloginaudit' ) . '\')" name="ala_delete_logs" type="submit" value="' . __( 'Delete all logs', 'aspexiloginaudit' ) . '" class="button-secondary" /></div>
                    </form>';

            return '<div style="float: left; margin-right: 10px;">'.$form.'</div>';
        }

        public function get_logs_per_page_filter( $filters = array() ) {

            $ret = '';

            $url = ASPEXILOGINAUDIT_ADMIN_URL.'&logs=true';

            $filters_hidden = $this->get_filters_hidden( $filters );

            $form = '<form method="post" action="'.$url.'" style="display: inline-block;" autocomplete="off">
                            <input type="hidden" name="ala_filter_submit" value="submit">'.$filters_hidden.'
                            '.wp_nonce_field( plugin_basename( __FILE__ ), 'ala_nonce_name' ).'
                            <div><b>' . __( 'Logs per page', 'aspexiloginaudit' ) . ':</b>&nbsp;<input type="text" name="ala_logs_per_page" value="'.$this->get_logs_per_page().'" size="3" />&nbsp;&nbsp;<input type="Submit" value="' . __( 'Apply', 'aspexiloginaudit' ) . '" class="button-secondary" /></div>
                        </form>';

            $ret = '<div style="float: left;">'.$form.'</div>';

            return $ret;
        }

        public function get_logs_per_page() {
            return ( isset( $this->config['logs_per_page'] ) && (int)$this->config['logs_per_page'] > 0 ) ? (int)$this->config['logs_per_page'] : $this->logs_per_page;
        }

        public function db_install() {

            global $wpdb;

            $charset_collate = $wpdb->get_charset_collate();

            $table_name = $wpdb->prefix . self::$table_name;

            if( $wpdb->get_var( "show tables like '{$table_name}'" ) != $table_name ) {

                $sql = "CREATE TABLE " . $table_name . " (
                  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                  status TINYINT UNSIGNED NOT NULL,
                  user VARCHAR(255) NOT NULL,
                  user_id INT NOT NULL,
                  user_email VARCHAR(255) NOT NULL,
                  ip VARCHAR(46) NOT NULL,
                  user_agent VARCHAR(255) NOT NULL,
                  referer VARCHAR(255) NOT NULL,
                  ip_blocked INT DEFAULT 0,
                  email_sent INT DEFAULT 0,
                  hidden INT DEFAULT 0,
                  date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ) $charset_collate;";

                require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

                dbDelta( $sql );
            }
        }
    }

    /* Let's start the show */
    global $aspexi_login_audit;

    $aspexi_login_audit = new AspexiLoginAudit();
}
