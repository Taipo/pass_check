<?php

class PasswordFilter {
    
    public static function hard_pass_check( $pass ) {
        
        $pass_strength = true;
        
        # banned alphanum combinations
        $_blacklist = array( '!@#$%^&*',
                             'aa123',
                             'abc',
                             'admin',
                             'asdf',
                             'dubsmash',
                             'football',
                             'g_czechout',
                             'ilove',
                             'letmein',
                             'login',
                             'master',
                             'monkey',
                             'pass',
                             'qwert',
                             'sunshine',
                             'test',
                             'zinch',
                             'zxcvb' );
        
        # prepare the pass
        $t_pass = strtolower( urldecode( trim( str_replace( ' ', '', $pass ) ) ) );
        
        # dynamically set minimum password length
        $min_pass_len = ( false !== ctype_alnum( $t_pass ) )? 14 : 13 ; // log2( 62^14 ) = 83.35-bits, log2( 95^13 ) = 85.40-bits
        
        // This password is weak. A 14 character alpha numeric pw would take 196.35 years to break ((62^14 / 2.0) / 1e15 / 31579200)
        // at 1000 parralel instances of 1 trillion hashes per second, whereas a 13 character password would take 3 years to crack,
        // and a 12 character password 18 days to crack
        if ( strlen( $pass ) < 12 ) $pass_strength = false;
    
        // Test the first 6 characters for digits. If you want to use only numbers as a password you will need a number longer than
        // 23 digits in length as a strong password log2( 10^24 ) = 79.72-bits i.e 1345 8954 6326 7594 3561 7659
        if ( is_numeric( substr( $t_pass, 0, 6 ) ) && ( strlen( $t_pass ) < 24 ) ) $pass_strength = false;
        
        # set an alphanumeric test $t_an_pass
        $t_an_pass = preg_replace( "/[^a-zA-Z0-9]/i", "", $t_pass );
     
        # prevent the use of lazy passwords within the first $min_pass_len characters of a password
        # passwords longer than $min_pass_len characters will at least have 83-bits of good password
        $t_pass = ( strlen( $t_pass ) > $min_pass_len ) ? substr( $t_pass, 0, $min_pass_len ) : $t_pass;
        
        # also test the aphanum within a password as well.
        $t_an_pass = ( strlen( $t_an_pass ) > $min_pass_len ) ? substr( $t_an_pass, 0, $min_pass_len ) : $t_an_pass; 
        
        // prevent the use of more than 1 set of reoccuring characters within the first $min_pass_len
        // characters in a password. ex: vv passes, as does vvv, vvdphh fails because of vv and hh,
        // vvvvdphdh fails because of two sets of vv
        preg_match_all( '/(.)\1+/', $t_pass, $matches );
        $result = array_combine( $matches[ 0 ], array_map( 'strlen', $matches[ 0 ] ) );
        if ( !empty( $result) ) {
            $r_chars = array_values( array_count_values( array_values( $result ) ) );
            if ( count( $r_chars ) == 1 ) {
                if ( $r_chars[ 0 ] > 1 ) $pass_strength = false;
            } elseif ( count( $r_chars ) > 1 ) {
                if ( ( ( int ) $r_chars[ 0 ] + ( int ) $r_chars[ 1 ] ) > 1 ) $pass_strength = false;
            }
        }
        
        // prevent the use of any reoccuring sets of 3 or 4 characters within the first $min_pass_len
        // characters in a password
        if ( false !== self::check_duplicate_phrases( $t_pass, 3 ) ) $pass_strength = false;
        if ( false !== self::check_duplicate_phrases( $t_pass, 4 ) ) $pass_strength = false;
        
        foreach ( $_blacklist as $badpass ) {
            if ( false !== strpos( $t_pass, $badpass ) || false !== strpos( $t_an_pass, $badpass ) ) {
                $pass_strength = false;
                break;
            }
        }
    
        if ( false === $pass_strength ) {
            return false;
        } else return true;    
    }
    private static function check_duplicate_phrases( $pass, $count ) {
        $pass_len = strlen( $pass );
        $t_array = array();
        $div = $pass_len - $count;
        # check for 3 char phrases, or occurences of 4 repeat chars
        for( $x = 0; $x <= $div; $x++ ) {
            $t_array[] = substr( $pass, $x, $count );
        }
        $f_array = array_unique( $t_array );
        if ( count( $t_array ) > count( $f_array ) ) {
            return true;
        }
        return false;    
    }
}
?>
