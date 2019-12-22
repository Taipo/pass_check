<?php

class PasswordFilter {
    
    private const PASS_MIN_LENGTH = 12;
    
    public static function pass_check( string $pass, $output_type = '' ) {
        
        # get uppercase array of blacklisted passwords
        $_blacklist = self::get_pw_blacklist();
        
        # initialise $pass_strength
        $pass_strength = true;
        
        # prepare the pass
        $t_pass = \urldecode( trim( str_replace( ' ', '', $pass ) ) );
        
        # dynamically set minimum password length
        $min_pass_len = self::set_min_pw_len( $t_pass ); // log2( 62^14 ) = 83.35-bits, log2( 95^13 ) = 85.40-bits

        # set an alphanumeric test $t_an_pass
        $t_an_pass = self::set_alphanum_pw( $t_pass );
     
        # prevent the use of lazy passwords within the first $min_pass_len characters of a password
        # passwords longer than $min_pass_len characters will at least have 83-bits of useable password entropy
        $t_pass_min = self::format_pw( $t_pass, $min_pass_len );
        
        # also test the aphanum within a password as well.
        $t_an_pass_min = self::format_pw( $t_an_pass, $min_pass_len );
        
        # finally run the tests and return
        $final_obj = new ArrayObject( self::pass_assertions( $pass, $t_pass_min, $t_an_pass_min, $_blacklist ) );
        
        # get pass fail status of password
        $status = self::get_boolean( $final_obj );
        
        # append to the object
        $final_obj->offsetSet( 'pass_check', $status );
        
        #output
        if ( $output_type == 'bool' ) {
            return $status;
        } elseif ( $output_type == 'object' ) {
            return $final_obj;
        } elseif ( $output_type == 'jbool' ) {
            return \json_encode( $status );      
        } elseif ( $output_type == '' || $output_type == 'json' ) {
            return \json_encode( $final_obj );
        }
    }
    private static function pass_assertions( $pass, $pass_1, $pass_2, $obvious_pwds ): object {
        $results = array();
        $results[ 'diceware_test' ]     = self::is_diceware( $pass );
	$results[ 'string_test' ]       = self::is_a_string( $pass, '' );
        $results[ 'pass_length' ]       = self::string_length( $pass, '' );
        $results[ 'is_numeric' ]        = self::is_a_number( $pass, '' );
        $results[ 'is_alphanumeric' ]   = self::is_alphanumeric( $pass, '' );
        $results[ 'pw_loop' ]           = self::is_pw_looped( $pass );
        $results[ 'dup_phrases' ]       = self::check_duplicate_phrases( $pass );
        $results[ 'is_obvious' ]        = self::is_pw_obvious( $obvious_pwds, $pass_1, $pass_2 );
        $results                        = ( object ) $results;
        return $results;
    }    
    private function set_min_pw_len( string $pass ): int {
        return ( false !== \ctype_alnum( $pass ) ) ? 14 : 13;
    }
    private function set_alphanum_pw( string $pass ): string {
        return \preg_replace( "/[^a-zA-Z0-9]/i", "", $pass );
    }
    private function format_pw( string $pass, int $min ): string {
        return ( \mb_strlen( $pass ) > $min ) ? \mb_substr( $pass, 0, $min ) : $pass; 
    }
    private function is_pw_looped( string $pass, $message = null, string $propertyPath = null ): array {
        \preg_match_all( '/(.)\1+/', $pass, $matches );
        $result = \array_combine( $matches[ 0 ], \array_map( 'mb_strlen', $matches[ 0 ] ) );
        if ( !empty( $result) ) {
            $r_chars = \array_values( array_count_values( array_values( $result ) ) );
            if ( \count( $r_chars ) == 1 ) {
                if ( $r_chars[ 0 ] > 1 ) return array(
                                            'is_pw_looped' => true, 'message' => \sprintf(
                                            $message ?: 'Password is expected to be random characters. Password "%s" repeats characters',
                                            $pass ), 'looped_characters' => \array_keys( $result )
                                        );
            } elseif ( \count( $r_chars ) > 1 ) {
                if ( ( ( int ) $r_chars[ 0 ] + ( int ) $r_chars[ 1 ] ) > 1 ) return true;
            }
        }
        return array( 'is_pw_looped' => false, 'message' => 'No loops detected' );
    }
    private function is_pw_obvious( array $obvious_pwds, string $pw1, string $pw2, $message = null, string $propertyPath = null ): array {
        $wordlist = array();
        foreach ( $obvious_pwds as $obvious) {
            if ( false !== \mb_strpos( mb_strtolower( $pw1 ), \mb_strtolower( $obvious ) ) || false !== \mb_strpos( mb_strtolower( $pw2 ), \mb_strtolower( $obvious ) ) ) {
                $wordlist[] = $obvious;
            }           
        }
        if ( !empty( $wordlist ) ) {
            return array(
                        'is_pw_obvious' => true, 'message' => \sprintf(
                        $message ?: 'Password is expected to be hard to guess. Password "%s" uses easy to guess phrases',
                        $pw1 ), 'obvious_phrase' => $wordlist
                    );
        } else return array(
                        'is_pw_obvious' => false, 'message' => \sprintf(
                        $message ?: 'Password is not using known easy password phrases' )
                    );
    }    
    private function get_pw_blacklist(): array {
        return \preg_split( '/\v+/', \file_get_contents( __DIR__ . '\password-blacklist.txt' ) );
    }
    private function get_boolean( $ob_result ): bool {
            $ob_result = ( object ) \json_decode( \json_encode( $ob_result ), true );
            $diceware = $ob_result->{ 'diceware_test' };
            if ( false !== $diceware[ 'is_dw' ] && 'fail' == $diceware[ 'status' ] ) return false;
            if ( false !== $diceware[ 'is_dw' ] && 'pass' == $diceware[ 'status' ] ) return true;
            $pass_length = $ob_result->{ 'pass_length' }; 
            if ( self::PASS_MIN_LENGTH > $pass_length[ 'string_length' ]  ) return false;
            $numeralis = $ob_result->{ 'is_numeric' };
            if ( false !== $numeralis[ 'is_a_number' ]  ) return false;
            $alphanumeralis = $ob_result->{ 'is_alphanumeric' };
            if ( false === $alphanumeralis[ 'is_alphanumeric' ]  ) return false;            
            $pass_loop = $ob_result->{ 'pw_loop' }; 
            if ( false !== $pass_loop[ 'is_pw_looped' ] ) return false;
            $duplication = $ob_result->{ 'dup_phrases' };
            if ( false !== $duplication[ 'check_duplicate_phrases' ] ) return false;
            $obvious_pw = $ob_result->{ 'is_obvious' };
            if ( false !== $obvious_pw[ 'is_pw_obvious' ] ) return false;
            return true;        
    }
    private function is_diceware( $pass ): array {
        $return_array = array( 'is_dw' => false, 'status' => 'fail', 'word_count' => 0, 'avg_len' => 0 );
        $pass_strength = 0;
        $repass = \mb_strtolower( $pass );
        $ws = \mb_substr_count( $repass, ' ' );
        if ( $ws >= 0 ) {
            $return_array[ 'is_dw' ] = false;
            $return_array[ 'status' ] = 'fail';
            $return_array[ 'word_count' ] = $ws;
            $return_array[ 'avg_len' ] = \mb_strlen( $pass );
            if ( $ws > 0 ) {
                $return_array[ 'is_dw' ] = true;
                $pass_array = \array_unique( \explode( ' ', $repass ) );
                $wc = \count( $pass_array );
                $return_array[ 'word_count' ] = $wc;
                # get average length
                $pass_val_array = array();
                foreach( $pass_array as $val ) {
                    $pass_val_array[] = \mb_strlen( $val );
                }
                $pass_val_array = \array_filter( $pass_val_array );
                $return_array[ 'avg_len' ] = \round( \array_sum( $pass_val_array ) / \count( $pass_val_array ) );
            }
            # evaluate
            if ( false !== $return_array[ 'is_dw' ] && $return_array[ 'word_count' ] > 6 && $return_array[ 'avg_len' ] > 3 ) {
                $return_array[ 'status' ] = 'pass';
            } elseif ( false === $return_array[ 'is_dw' ] || $return_array[ 'word_count' ] <= 6 ) $return_array[ 'status' ] = 'fail';
            return $return_array;
        }
    }
    
    private static function check_duplicate_phrases( string $pass, $message = null, string $propertyPath = null ): array {
        for( $n = 3; $n <= 4; $n++ ) {
            $pass_len = \mb_strlen( $pass );
            $t_array = array();
            $div = $pass_len - $n;
            # check for 3 char phrases, or occurences of 4 repeat chars
            for( $x = 0; $x <= $div; $x++ ) {
                $t_array[] = \mb_substr( $pass, $x, $n );
            }
            $f_array = \array_unique( $t_array, SORT_STRING );
            if ( \count( $t_array ) > count( $f_array ) ) {
                $diff = array();
                for( $t = 0; $t < \count( $f_array ); $t++ ) {
                    if ( !\array_key_exists( $t, $f_array ) ) $diff[] = $t_array[ $t ];
                }
            }
        }
        if ( !empty( $diff ) ) {
            return array( 'check_duplicate_phrases' => true, 'message' => \sprintf(
                                       $message ?: 'Password is expected to be random characters. Password "%s" contains duplicate phrases',
                                       $pass ), 'phrase_duplicates' => $diff );
        } else return array( 'check_duplicate_phrases' => false, 'message' => \sprintf(
                           $message ?: 'Password "%s" contains no duplicate phrases',
                           $pass ) );   
    }
    
    public static function string_length( $value, $message = null, string $propertyPath = null ): array {
        # A 14 character alpha numeric pw would take 196.35 years to break ((62^14 / 2.0) / 1e15 / 31579200)
        # at 1000 parallel instances of 1 trillion hashes per second, whereas a 13 character password would take 3 years to crack,
        # and a 12 character password 18 days to crack
        $str_len = \mb_strlen( $value );
        if ( $str_len < self::PASS_MIN_LENGTH ) {
            return array( 'string_length' => $str_len, 'message' => \sprintf( $message ?: 'Password is expected to be longer than ' . self::PASS_MIN_LENGTH . ' characters in length. Password is "%s" characters long',
                        $str_len,
                        ( self::PASS_MIN_LENGTH - $str_len ) ) );
        }
        return array( 'string_length' => $str_len, 'message' => \sprintf( $message ?: 'Password is "%s" characters long',
                        $str_len
                        ) );
    }
    
    public static function is_alphanumeric( $value, $message = null, string $propertyPath = null ): array {
        if ( false === ( bool ) preg_match( '/[a-z]/', $value ) || false === ( bool ) preg_match( '/[A-Z]/', $value ) || false === ( bool ) preg_match( '/[0-9]/', $value ) ) {
            return array( 'is_alphanumeric' => false, 'message' => \sprintf( $message ?: 'Password "%s" expected to contain alphanumeric characters including at least one uppercase letter', 
                        static::string_check( $value ) ) );
        } else return array( 'is_alphanumeric' => true, 'message' => \sprintf( $message ?: 'Password "%s" contains alphanumeric characters including at least one uppercase letter', 
                        static::string_check( $value ) ) );
    }
    public static function is_a_number( $value, $message = null, string $propertyPath = null ): array {
        # Test the first 6 characters for digits. If you want to use only numbers as a password you will need a number longer than
        # 23 digits in length as a strong password log2( 10^24 ) = 79.72-bits i.e 1345 8954 6326 7594 3561 7659
        if ( ( \is_numeric( \mb_substr( $value, 0, 6 ) ) && ( \mb_strlen( $value ) < 24 ) ) ) {
            return array( 'is_a_number' => true, 'message' => \sprintf( $message ?: 'Password "%s" expected to be at least alphanumeric. If you want to use only numbers as a password you will need a number longer than 23 digits in length as a strong password log2( 10^24 ) = 79.72-bits i.e 1345 8954 6326 7594 3561 7659',
                        static::string_check( $value )
                        ) );
        }
        return array( 'is_a_number' => false, 'message' => '' );
    }    
    
    public static function is_a_string( $value, $message = null, string $propertyPath = null ): array {
        if ( !\is_string( $value ) ) {
            return array( 'is_a_string' => false, 'message' => \sprintf( $message ?: 'Password "%s" expected to be a string, type %s given.',
                        static::string_check( $value ),
                        \gettype( $value )
                        ) );
        }
        return array( 'is_a_string' => true, 'message' => '' );
    }
    protected static function string_check( $value ): string {
        $result = \gettype( $value );
        if ( \is_bool( $value ) ) {
            $result = $value ? '<TRUE>' : '<FALSE>';
        } elseif ( \is_scalar( $value ) ) {
            $val = (string)$value;
            if ( \strlen($val) > 100) {
                $val = \substr($val, 0, 97).'...';
            }
            $result = $val;
        } elseif ( \is_array( $value ) ) {
            $result = '<ARRAY>';
        } elseif ( \is_object( $value ) ) {
            $result = \get_class( $value );
        } elseif ( \is_resource( $value ) ) {
            $result = \get_resource_type( $value );
        } elseif ( null === $value ) {
            $result = '<NULL>';
        }
        return $result;
    }
}
