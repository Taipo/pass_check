<?php
    require_once( 'class_password_filter.php' );
    $PasswordFilter = new PasswordFilter();
    # choose from either bool, object or json for output type
    var_dump( $PasswordFilter->pass_check( 'TestPasswordHere', 'json' ) );
?>
