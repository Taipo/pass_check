<?php
    require_once( 'class_password_filter.php' );
    $PasswordFilter = new PasswordFilter();
    # choose from either bool, object, json or jbool (json boolean) for output type
    var_dump( $PasswordFilter->pass_check( 'TestPassw0rdHere', 'object' ) );
?>
