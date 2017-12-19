<?php

/**
 * Lockdown extension - implements restrictions on individual
 * namespaces and special pages.
 *
 * @file
 * @ingroup Extensions
 * @author Daniel Kinzler, brightbyte.de
 * @copyright © 2007 Daniel Kinzler
 * @license GNU General Public Licence 2.0 or later
 */

if ( !defined( 'MEDIAWIKI' ) ) {
	echo( "This file is an extension to the MediaWiki software and cannot be "
		  . "used standalone.\n" );
	die( 1 );
}

$wgExtensionCredits['other'][] = [
	'path' => __FILE__,
	'name' => 'Lockdown',
	'author' => [
		'Daniel Kinzler',
		'Platonides',
		'...'
	],
	'url' => 'https://mediawiki.org/wiki/Extension:Lockdown',
	'descriptionmsg' => 'lockdown-desc',
	'license-name' => 'GPL-2.0+'
];

$wgMessagesDirs['Lockdown'] = __DIR__ . '/i18n';

$wgNamespacePermissionLockdown = [];
$wgSpecialPageLockdown = [];
$wgActionLockdown = [];

$wgHooks['getUserPermissionsErrors'][] = 'lockdownUserPermissionsErrors';
$wgHooks['MediaWikiPerformAction'][] = 'lockdownMediawikiPerformAction';
$wgHooks['SearchableNamespaces'][] = 'lockdownSearchableNamespaces';
$wgHooks['SearchGetNearMatchComplete'][] = 'lockdownSearchGetNearMatchComplete';

/**
 * Return an error if the user is locked out of this namespace.
 *
 * @param Title $title that is being requested
 * @param User $user who is requesting
 * @param string $action they are performing
 * @param MessageSpecifier|array|string|bool|null &$result response
 * @return bool
 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
 */
function lockdownUserPermissionsErrors(
	Title $title,
	User $user,
	$action,
	&$result = null
) {
	global $wgNamespacePermissionLockdown, $wgSpecialPageLockdown,
		$wgWhitelistRead, $wgLang;

	$result = null;

	// don't impose extra restrictions on UI pages
	if ( $title->isCssJsSubpage() ) {
		return true;
	}

	if ( $action == 'read' && is_array( $wgWhitelistRead ) ) {
		// don't impose read restrictions on whitelisted pages
		if ( in_array( $title->getPrefixedText(), $wgWhitelistRead ) ) {
			return true;
		}
	}

	$groups = null;
	$ns = $title->getNamespace();
	if ( NS_SPECIAL == $ns ) {
		foreach ( $wgSpecialPageLockdown as $page => $g ) {
			if ( !$title->isSpecial( $page ) ) {
				continue;
			}
			$groups = $g;
			break;
		}
	} else {
		$groups = @$wgNamespacePermissionLockdown[$ns][$action];
		if ( $groups === null ) {
			$groups = @$wgNamespacePermissionLockdown['*'][$action];
		}
		if ( $groups === null ) {
			$groups = @$wgNamespacePermissionLockdown[$ns]['*'];
		}
	}

	if ( $groups === null ) {
		// no restrictions
		return true;
	}

	if ( !$groups ) {
		// no groups allowed

		$result = [
			'badaccess-group0'
		];

		return false;
	}

	$ugroups = $user->getEffectiveGroups();

	$match = array_intersect( $ugroups, $groups );

	if ( $match ) {
		# group is allowed - keep processing
		$result = null;
		return true;
	} else {
		# group is denied - abort
		$groupLinks = array_map( [ 'User', 'makeGroupLinkWiki' ], $groups );

		$result = [
			'badaccess-groups',
			$wgLang->commaList( $groupLinks ),
			count( $groups )
		];

		return false;
	}
}

/**
 * Determine if the user is a member of a group that is allowed to
 * perform the given action.
 *
 * @param OutputPage $output n/a
 * @param Article $article n/a
 * @param Title $title n/a
 * @param User $user whose groups we will check
 * @param WebRequest $request used to get the raw action
 * @param MediaWiki $wiki used to get the parsed action
 * @return bool
 * @see https://www.mediawiki.org/wiki/Manual:Hooks/MediaWikiPerformAction
 */
function lockdownMediawikiPerformAction(
	OutputPage $output,
	Article $article,
	Title $title,
	User $user,
	WebRequest $request,
	MediaWiki $wiki
) {
	global $wgActionLockdown, $wgLang;

	$action = $wiki->getAction();

	if ( !isset( $wgActionLockdown[$action] ) ) {
		return true;
	}

	$groups = $wgActionLockdown[$action];
	if ( $groups === null ) {
		return true;
	}
	if ( !$groups ) {
		return false;
	}

	$ugroups = $user->getEffectiveGroups();
	$match = array_intersect( $ugroups, $groups );

	if ( $match ) {
		return true;
	} else {
		$groupLinks = array_map( [ 'User', 'makeGroupLinkWiki' ], $groups );

		$err = [
			'badaccess-groups', $wgLang->commaList( $groupLinks ),
			count( $groups )
		];
		throw new PermissionsError( $request->getVal( 'action' ), [ $err ] );
	}
}

/**
 * Filter out the namespaces that the user is locked out of
 *
 * @param array &$searchableNs Is filled with searchable namespaces
 * @return bool
 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchableNamespaces
 */
function lockdownSearchableNamespaces( array &$searchableNs ) {
	$user = RequestContext::getMain()->getUser();
	$ugroups = $user->getEffectiveGroups();

	foreach ( $searchableNs as $ns => $name ) {
		if ( !lockdownNamespace( $ns, $ugroups ) ) {
			unset( $searchableNs[$ns] );
		}
	}
	return true;
}

/**
 * Convenience function for internal use only. Determine if one of the
 * list of groups is allowed in this namespace.
 *
 * @param int $ns Namespace being checked
 * @param array $ugroups list of user's groups
 * @return bool
 */
function lockdownNamespace( $ns, array $ugroups ) {
	global $wgNamespacePermissionLockdown;

	$groups = @$wgNamespacePermissionLockdown[$ns]['read'];
	if ( $groups === null ) {
		$groups = @$wgNamespacePermissionLockdown['*']['read'];
	}
	if ( $groups === null ) {
		$groups = @$wgNamespacePermissionLockdown[$ns]['*'];
	}

	if ( is_array( $groups ) && !array_intersect( $ugroups, $groups ) ) {
		return false;
	}

	return true;
}

/**
 * Stop a Go search for a hidden title to send you to the login
 * required page. Will show a no such page message instead.
 *
 * @param string $searchterm the term being searched
 * @param Title $title Title the user is being sent to
 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchGetNearMatchComplete
 */
function lockdownSearchGetNearMatchComplete(
	$searchterm,
	Title $title = null
) {
	global $wgUser;

	if ( $title ) {
		$ugroups = $wgUser->getEffectiveGroups();
		if ( !lockdownNamespace( $title->getNamespace(), $ugroups ) ) {
			$title = null;
		}
	}
}
