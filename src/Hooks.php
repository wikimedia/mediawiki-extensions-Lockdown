<?php

/**
 * Lockdown extension - implements restrictions on individual
 * namespaces and special pages.
 *
 * Copyright (C) 2007, 2012, 2016  Daniel Kinzler
 * Copyright (C) 2017  NicheWork, LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * @file
 * @ingroup Extensions
 * @author Daniel Kinzler, brightbyte.de
 * @author Mark A. Hershberger <mah@nichework.com>
 * @license GPL-2.0-or-later
 */
namespace MediaWiki\Extensions\Lockdown;

use Article;
use MediaWiki;
use OutputPage;
use PermissionsError;
use RequestContext;
use Title;
use User;
use UserGroupMembership;
use WebRequest;

/**
 * Holds the hooks for the Lockdown extension.
 */
class Hooks {

	private static function getGroupLinks( $groups ) {
		$links = [];
		foreach ( $groups as $group ) {
			$links[] = UserGroupMembership::getLink(
				$group, RequestContext::getMain(), 'wiki'
			);
		}
		return $links;
	}

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
		if ( $title->isUserConfigPage() ) {
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
			$groupLinks = self::getGroupLinks( $groups );

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
			$groupLinks = self::getGroupLinks( $groups );

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
		if ( $groups === "*" ) {
			$groups = null;
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
		$groups = self::namespaceGroups( $ns );
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
	 * @param Title|null $title Title the user is being sent to
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchGetNearMatchComplete
	 */
	public static function onSearchGetNearMatchComplete(
		$searchterm,
		Title $title = null
	) {
		if ( $title ) {
			$ugroups = RequestContext::getMain()->getUser()->getEffectiveGroups();
			if ( !self::namespaceCheck( $title->getNamespace(), $ugroups ) ) {
				$title = null;
			}
		}
	}
}
