<?php
/**
 * Plugin Name: Ninja Forms Anti-Spam Enhancer
 * Description: Adds lightweight anti-spam features (nonce, IP rate limiting) to Ninja Forms. Add a field with a key of 'antispam' to form to enable.
 * Version: 1.0
 * Author: Nathan Turner
 */

add_filter('ninja_forms_submit_data', 'nf_antispam_enforce', 10, 1);

function nf_antispam_enforce($form_data) {
    $fields = $form_data['fields'];
    $form_id = $form_data['form_id'];
    $ip = $_SERVER['REMOTE_ADDR'];

    $has_errors = false;
    $error_msg = '';
    $field_map = [];
	$field_id = 1;
    foreach ($fields as $k => $field) {
        $field_map[$field['key']] = $field['value'];
		if($field['key'] == 'submit')
			$field_id = $k;
    }


    if(array_key_exists('antispam', $field_map)) {

        $limit_per_hour = get_option('nf_submission_limit', 10);
		
		// Nonce check
        $keyn = 'nf_secure_submission' . md5($form_id . $ip);
        if (get_transient($keyn)) {
			if(!wp_verify_nonce(get_transient($keyn), 'nf_secure_submission')){
				$has_errors = true;
            	$error_msg = 'Invalid or expired submission.';
			}       
        } else {
            set_transient($keyn, wp_create_nonce('nf_secure_submission'), 600); // 10 minute
        }

        // Rate limiting: max submissions per 3600 seconds (1 hour)
        $key = 'nf_submissions_' . md5($form_id . $ip);
        $submissions = get_transient($key);
        if (!is_array($submissions)) {
            $submissions = [];
        }

        $now = time();
        $one_hour_ago = $now - 3600;

        // Remove old entries
        $submissions = array_filter($submissions, function($timestamp) use ($one_hour_ago) {
            return $timestamp > $one_hour_ago;
        });

        if (count($submissions) >= $limit_per_hour) {
            $has_errors = true;
            $error_msg = 'You have reached the submission limit ('.$limit_per_hour.' per hour). Please wait.';
        } else {
            // Add current timestamp and store
            $submissions[] = $now;
            set_transient($key, $submissions, 3600); // Keep data for 1 hour
        }
    }

    if ($has_errors) {
        $form_data['errors']['fields'][1] = $error_msg;
    }
    
    return $form_data;
}

add_action('admin_menu', function () {
    add_menu_page(
        'Ninja Form Rate Limits',
        'Ninja Form Limits',
        'manage_options',
        'ninja-form-limits',
        'nf_form_limits_settings_page',
        'dashicons-shield',
        80
    );
});

function nf_form_limits_settings_page() {
    ?>
    <div class="wrap">
        <h1>Ninja Form Rate Limits</h1>
        <form method="post" action="options.php">
            <?php
            settings_fields('nf_form_limits_group');
            do_settings_sections('ninja-form-limits');
            submit_button();
            ?>
        </form>
    </div>
    <?php
}

add_action('admin_init', function () {
    register_setting('nf_form_limits_group', 'nf_submission_limit', [
        'type' => 'integer',
        'sanitize_callback' => 'absint',
        'default' => 10,
    ]);

    add_settings_section(
        'nf_rate_limit_section',
        'Rate Limiting',
        function () {
            echo '<p>Configure global rate limiting for Ninja Forms submissions.</p>';
        },
        'ninja-form-limits'
    );

    add_settings_field(
        'nf_submission_limit',
        'Submissions Per Hour',
        function () {
            $value = get_option('nf_submission_limit', 10);
            echo '<input type="number" name="nf_submission_limit" min="1" value="' . esc_attr($value) . '" />';
        },
        'ninja-form-limits',
        'nf_rate_limit_section'
    );
});


add_action('wp_footer', function() {
    ?>
    <script>
    document.addEventListener('nfFormReady', function(e) {
      const forms = document.querySelectorAll('.nf-form');
      forms.forEach(form => {
        form.addEventListener('nfFormError', function() {
          const submitButtons = form.querySelectorAll('.submit-wrap input[type="submit"], .submit-wrap button');
          submitButtons.forEach(btn => btn.disabled = false);
        });
      });
    });
    </script>
    <?php
});