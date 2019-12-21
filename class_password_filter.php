<?php

class PasswordFilter {
    private const PASS_MIN_LENGTH = 12;
    
    public static function hard_pass_check( string $pass ): bool {
        
        # get uppercase array of blacklisted passwords
        $_blacklist = self::get_pw_blacklist();
        
        # set as uppercase
        $pass = strtoupper( $pass );
        
        # initialise $pass_strength
        $pass_strength = true;
        
        # prepare the pass
        $t_pass = urldecode( trim( str_replace( ' ', '', $pass ) ) );
        
        # dynamically set minimum password length
        $min_pass_len = self::set_min_pw_len( $t_pass ); // log2( 62^14 ) = 83.35-bits, log2( 95^13 ) = 85.40-bits
        
        // This password is weak. A 14 character alpha numeric pw would take 196.35 years to break ((62^14 / 2.0) / 1e15 / 31579200)
        // at 1000 parallel instances of 1 trillion hashes per second, whereas a 13 character password would take 3 years to crack,
        // and a 12 character password 18 days to crack
        if ( mb_strlen( $pass ) <= self::PASS_MIN_LENGTH ) {
            $pass_strength = false;
        }
    
        // Test the first 6 characters for digits. If you want to use only numbers as a password you will need a number longer than
        // 23 digits in length as a strong password log2( 10^24 ) = 79.72-bits i.e 1345 8954 6326 7594 3561 7659
        if ( is_numeric( substr( $t_pass, 0, 6 ) ) && ( strlen( $t_pass ) < 24 ) ) $pass_strength = false;
        
        # set an alphanumeric test $t_an_pass
        $t_an_pass = self::set_alphanum_pw( $t_pass );
     
        # prevent the use of lazy passwords within the first $min_pass_len characters of a password
        # passwords longer than $min_pass_len characters will at least have 83-bits of useable password entropy
        $t_pass_min = self::format_pw( $t_pass, $min_pass_len );
        
        # also test the aphanum within a password as well.
        $t_an_pass_min = self::format_pw( $t_an_pass, $min_pass_len );
        
        // prevent the use of more than 1 pair of reoccuring characters within the first $min_pass_len
        // characters in a password. ex: vv passes, as does vvv, vvdphh fails because of vv and hh,
        // vvvvdphdh fails because of two sets of vv
        self::is_pw_looped( $t_pass_min );
        
        // prevent the use of any reoccuring sets of 3 or 4 characters within the first $min_pass_len
        // characters in a password
        if ( false !== self::check_duplicate_phrases( $t_pass_min, 3 ) ) $pass_strength = false;
        if ( false !== self::check_duplicate_phrases( $t_pass_min, 4 ) ) $pass_strength = false;

        if ( self::is_pw_obvious( $_blacklist, $t_pass_min, $t_an_pass_min ) ) $pass_strength = false;

        if ( false === $pass_strength ) {
            return false;
        } else return true;    
    }
    private function set_min_pw_len( string $pass ): int {
        return ( false !== ctype_alnum( $pass ) ) ? 14 : 13;
    }
    private function set_alphanum_pw( string $pass ): string {
        return preg_replace( "/[^a-zA-Z0-9]/i", "", $pass );
    }
    private function format_pw( string $pass, int $min ): string {
        return ( strlen( $pass ) > $min ) ? substr( $pass, 0, $min ) : $pass; 
    }
    private function is_pw_looped( string $pass ): bool {
        preg_match_all( '/(.)\1+/', $pass, $matches );
        $result = array_combine( $matches[ 0 ], array_map( 'strlen', $matches[ 0 ] ) );
        if ( !empty( $result) ) {
            $r_chars = array_values( array_count_values( array_values( $result ) ) );
            if ( count( $r_chars ) == 1 ) {
                if ( $r_chars[ 0 ] > 1 ) return true;
            } elseif ( count( $r_chars ) > 1 ) {
                if ( ( ( int ) $r_chars[ 0 ] + ( int ) $r_chars[ 1 ] ) > 1 ) return true;
            }
        }
        return false;
    }
    private function is_pw_obvious( array $obvious_pwds, string $pw1, string $pw2 ): bool {
        foreach ( $obvious_pwds as $obvious) {
            if ( mb_strpos( mb_strtolower( $pw1 ), mb_strtolower( $obvious ) ) !== false) {
                return true;
            }
            if ( mb_strpos( mb_strtolower( $pw2 ), mb_strtolower( $obvious ) ) !== false) {
                return true;
            }            
        }
        return false;
    }    
    private function get_pw_blacklist(): array {
        return preg_split( '/\v+/', mb_strtoupper(
               file_get_contents( __DIR__ . '\password-blacklist.txt' ) ) );
    }
    private static function check_duplicate_phrases( string $pass, int $count ): bool {
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
