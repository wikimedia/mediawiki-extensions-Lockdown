<?php

/**
 * Lockdown extension - implements restrictions on individual
 * namespaces and special pages.
 *
 * @file
 * @ingroup Extensions
 * @author Daniel Kinzler, brightbyte.de
 * @author Mark A. Hershberger, NicheWork, LLC
 * @copyright © 2007, 2016 Daniel Kinzler
 * @copyright © 2017 NicheWork, LLC
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
		'Mark A. Hershberger',
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

$wgHooks['getUserPermissionsErrors'][] = 'Lockdown::onGetUserPermissionsErrors';
$wgHooks['MediaWikiPerformAction'][] = 'Lockdown::onMediawikiPerformAction';
$wgHooks['SearchableNamespaces'][] = 'Lockdown::onSearchableNamespaces';
$wgHooks['SearchGetNearMatchComplete'][]
	= 'Lockdown::onSearchGetNearMatchComplete';

class Lockdown {

	/**
	 * Fetch an appropriate permission error (or none!)
	 *
	 * @param Title $title being checked
	 * @param User $user whose access is being checked
	 * @param string $action being checked
	 * @param MessageSpecifier|array|string|bool|null &$result User
	 *   permissions error to add. If none, return true. $result can be
	 *   returned as a single error message key (string), or an array of
	 *   error message keys when multiple messages are needed
	 * @return bool
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
	 */
	public static function onGetUserPermissionsErrors(
		Title $title,
		User $user,
		$action,
		&$result = null
	) {
		global $wgSpecialPageLockdown, $wgWhitelistRead, $wgLang;

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
			$groups = self::namespaceGroups( $ns, $action );
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
	public static function onMediawikiPerformAction(
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
			throw new PermissionsError(
				$request->getVal( 'action' ), [ $err ]
			);
		}
	}

	/**
	 * Filter out the namespaces that the user is locked out of
	 *
	 * @param array &$searchableNs Is filled with searchable namespaces
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchableNamespaces
	 */
	public static function onSearchableNamespaces( array &$searchableNs ) {
		$user = RequestContext::getMain()->getUser();
		$ugroups = $user->getEffectiveGroups();

		foreach ( $searchableNs as $ns => $name ) {
			if ( !self::namespaceCheck( $ns, $ugroups ) ) {
				unset( $searchableNs[$ns] );
			}
		}
	}

	/**
	 * Get groups that this action is restricted to in this namespace.
	 *
	 * @param int $ns to check
	 * @param string $action to check (default: read)
	 * @return null|array of groups
	 */
	protected static function namespaceGroups( $ns, $action = 'read' ) {
		global $wgNamespacePermissionLockdown;

		$groups = isset( $wgNamespacePermissionLockdown[$ns][$action] )
				? $wgNamespacePermissionLockdown[$ns][$action]
				: null;
		if ( $groups === null ) {
			$groups = isset( $wgNamespacePermissionLockdown['*'][$action] )
					? $wgNamespacePermissionLockdown['*'][$action]
					: null;
		}
		if ( $groups === null ) {
			$groups = isset( $wgNamespacePermissionLockdown[$ns]['*'] )
					? $wgNamespacePermissionLockdown[$ns]['*']
					: null;
		}
		return $groups;
	}

	/**
	 * Determine if this the user has the group to read this namespace
	 *
	 * @param int $ns to check
	 * @param array $ugroups that the user is in
	 * @return bool false if the user does not have permission
	 */
	protected static function namespaceCheck( $ns, array $ugroups ) {
		$groups = namespaceGroups( $ns );
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
	public static function onSearchGetNearMatchComplete(
		$searchterm,
		Title $title = null
	) {
		global $wgUser;

		if ( $title ) {
			$ugroups = $wgUser->getEffectiveGroups();
			if ( !self::namespaceCheck( $title->getNamespace(), $ugroups ) ) {
				$title = null;
			}
		}
	}
}
