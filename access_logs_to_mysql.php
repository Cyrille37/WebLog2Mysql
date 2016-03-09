#!/usr/bin/env php
<?php
/**
 * Web access logs to Mysql database.
 */

error_reporting(E_ALL);

$dbname = 'tmp_logs';
$dbuser = 'root';
$dbpwd = 'root';

if( $argc != 2 )
{
	echo 'load access_log files into mysql "'.$dbname.'"',"\n";
	echo $argv[0], ' <existing folder>', "\n";
	die("abort\n");
}

$folder = $argv[1];
$folder = str_replace('file://','',$folder);
$folder = str_replace('%20',' ',$folder);

if( ! file_exists($folder) )
{
	echo 'folder not exists "'.$folder.'"',"\n";
	die("abort\n");
}

echo 'Loading access_log files in "'.$folder.'" into mysql database "'.$dbname.'"',"\n";

$pdo = create_database($dbname,$dbuser,$dbpwd);

$stats = read_folder($folder, $pdo);

echo var_export( $stats, true ),"\n";

function create_database($dbname,$user,$pw)
{
	//$pdo = new PDO('mysql:dbname='.$dbname.';socket=/var/run/mysqld/mysqld.sock;charset=UTF8', $user, $pw);
	$pdo = new PDO('mysql:socket=/var/run/mysqld/mysqld.sock;charset=UTF8', $user, $pw);
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	$pdo->exec('DROP SCHEMA IF EXISTS `'.$dbname.'`');
	$pdo->exec('CREATE SCHEMA `'.$dbname.'`');
	$pdo->exec('USE `'.$dbname.'`');

	$pdo->exec('DROP TABLE IF EXISTS `logs`');
	$pdo->exec('
		CREATE TABLE logs (
		`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
		`ip` VARCHAR(15) NULL,
		/* `date` DATETIME NULL, */
		`date` VARCHAR(40) NULL,
		`user` VARCHAR(100) NULL,
		`method` VARCHAR(10) NULL,
		`url` TEXT NULL,
		`protocol` VARCHAR(10) NULL,
		`status` INT(10) UNSIGNED NULL,
		`size` INT(10) UNSIGNED NULL,
		`referer` TEXT NULL,
		`browser` VARCHAR(255) NULL,
		`filename` VARCHAR(255) NULL,
		PRIMARY KEY (`id`)
	)' );
	return $pdo ;
}

function read_folder( $folder, PDO $pdo )
{
	$filesCount = 0 ;
	$linesCount = 0 ;
	$linesError = 0 ;
	$dir = new \DirectoryIterator( $folder );
	foreach( $dir as $fileinfo )
	{
		if( $fileinfo->isDot() )
			continue ;
		if( $fileinfo->isDir() )
		{
			echo '> ', $folder.'/'.$fileinfo->getFilename(),"\n";
			$stats = read_folder( $folder.'/'.$fileinfo->getFilename(), $pdo );
			$filesCount+=$stats['filesCount'];
			$linesCount+=$stats['linesCount'];
			$linesError+=$stats['linesError'];
			continue ;
		}
		if( ! $fileinfo->isFile())
			continue ;
		if( ! preg_match('#access#', $fileinfo->getFilename()) )
			continue ;

		echo $fileinfo->getFilename(),"\n";
		$stats = read_log( $folder, $fileinfo->getFilename(), $pdo );
		$filesCount ++ ;
		$linesCount += $stats['linesCount'] ;
		$linesError += $stats['linesError'] ;
	}

	return ['filesCount'=>$filesCount,'linesCount'=>$linesCount,'linesError'=>$linesError ];
}

function read_log( $folder, $filename, PDO $pdo)
{
	$fp = fopen( 'compress.zlib://'.$folder.'/'.$filename, 'rb' );
	$linesCount = 0 ;
	$linesError = 0 ;
	$ips = [] ;
	$pdo->beginTransaction();

	while( $line = fgets( $fp ) )
	{
		$linesCount ++ ;
		try
		{
			$data = decode_log( $line );
			if( $data == null )
			{
				$linesError ++ ;
				echo 'ERROR: Unable to decode line ',$linesCount,' of file "',$filename.'"',"\n";
				continue ;
			}
		}
		catch( \Exception $ex )
		{
			throw new \Exception( $ex->getMessage() . ' while reading line '.$linesCount.' of file "'.$filename.'"' );
		}

		$sth = $pdo->prepare('INSERT logs (ip,user,date,method,url,protocol,status,size,referer,browser,filename) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
		$data['filename'] = $filename ;
		$sth->execute( array_values( $data ));

		if( ! isset( $ips[$data['ip']] ) )
			$ips[$data['ip']] = 1 ;
		else
			$ips[$data['ip']] ++ ;
	}

	$pdo->commit();
	fclose( $fp );

	return ['linesCount' => $linesCount, 'ips_count' => count($ips), 'linesError' => $linesError ];
}

function decode_log( &$line )
{
		$matches = [];
		// 89.158.149.192 - - [03/Dec/2015:21:31:33 +0100] "GET /wp-content/uploads/2015/07/image-7-268x268.jpg HTTP/1.1" 200 12924 "http://blog.coopaxis.fr/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:42.0) Gecko/20100101 Firefox/42.0"
		// 5.196.33.194 - - [13/Nov/2015:07:09:02 +0100] "POST /sparql HTTP/1.1" 200 204357 "-" "Java/1.7.0_85"
		if( preg_match('#^([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) [-] (.*?) \[(.*?)\] "(.*?) (.*?) (.*?)" ([0-9]{3}) ([0-9]*?) "(.*?)" "(.*?)"#', $line, $matches) )
		{
			$d = new DateTime($matches[3]);

			return [
			'ip' => $matches[1],
			'user' => $matches[2],
			'date' => $d->format('Y-m-d H:i:s'),
			'method' => $matches[4],
			'url' => $matches[5],
			'protocol' => $matches[6],
			'status' => $matches[7],
			'size' => $matches[8],
			'referer' => $matches[9],
			'browser' => $matches[10],
			];
		}
		// 89.158.149.192 - - [13/Nov/2015:08:30:36 +0100] "-" 400 0 "-" "-"
		if( preg_match('#^([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}) [-] (.*?) \[(.*?)\] "(.*?)" ([0-9]{3}) ([0-9]*?) "(.*?)" "(.*?)"#', $line, $matches) )
		{
			$d = new DateTime($matches[3]);

			return [
			'ip' => $matches[1],
			'user' => $matches[2],
			'date' => $d->format('Y-m-d H:i:s'),
			'method' => '-',
			'url' => $matches[4],
			'protocol' => '-',
			'status' => $matches[5],
			'size' => $matches[6],
			'referer' => $matches[7],
			'browser' => $matches[8],
			];
		}

		//throw new Exception('Failed to decode line');
		return null ;

}
