<?php
    require_once( 'class_password_filter.php' );
    $PasswordFilter = new PasswordFilter();
    var_dump( PasswordFilter::hard_pass_check( 'testpasswordhere' ) );
?>