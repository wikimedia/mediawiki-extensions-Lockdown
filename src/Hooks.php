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
namespace MediaWiki\Extension\Lockdown;

use Article;
use MediaWiki\Actions\ActionEntryPoint;
use MediaWiki\Hook\MediaWikiPerformActionHook;
use MediaWiki\Permissions\Hook\GetUserPermissionsErrorsHook;
use MediaWiki\Search\Hook\SearchableNamespacesHook;
use MediaWiki\Search\Hook\SearchGetNearMatchCompleteHook;
use MediaWiki\User\UserGroupManager;
use MessageSpecifier;
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
class Hooks implements
	GetUserPermissionsErrorsHook,
	MediaWikiPerformActionHook,
	SearchableNamespacesHook,
	SearchGetNearMatchCompleteHook
{
	/**
	 * @var UserGroupManager
	 */
	private $userGroupManager;

	/**
	 * @param UserGroupManager $userGroupManager
	 */
	public function __construct( UserGroupManager $userGroupManager ) {
		$this->userGroupManager = $userGroupManager;
	}

	/**
	 * @param array $groups
	 * @return array
	 */
	private function getGroupLinks( array $groups ) {
		$links = [];
		foreach ( $groups as $group ) {
			$links[] = UserGroupMembership::getLinkWiki( $group, RequestContext::getMain() );
		}
		return $links;
	}

	/**
	 * Fetch an appropriate permission error (or none!)
	 *
	 * @param Title $title being checked
	 * @param User $user whose access is being checked
	 * @param string $action being checked
	 * @param array|string|MessageSpecifier &$result User
	 *   permissions error to add. If none, return true. $result can be
	 *   returned as a single error message key (string), or an array of
	 *   error message keys when multiple messages are needed
	 * @return bool
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
	 */
	public function onGetUserPermissionsErrors( $title, $user, $action, &$result ) {
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
			$groups = $this->namespaceGroups( $ns, $action );
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

		$ugroups = $this->userGroupManager->getUserEffectiveGroups( $user );

		$match = array_intersect( $ugroups, $groups );

		if ( $match ) {
			# group is allowed - keep processing
			return true;
		}

		# group is denied - abort
		$groupLinks = $this->getGroupLinks( $groups );

		$result = [
			'badaccess-groups',
			$wgLang->commaList( $groupLinks ),
			count( $groups )
		];

		return false;
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
	 * @param ActionEntryPoint $wiki used to get the parsed action
	 * @return bool
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/MediaWikiPerformAction
	 */
	public function onMediaWikiPerformAction(
		$output,
		$article,
		$title,
		$user,
		$request,
		$wiki
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

		$ugroups = $this->userGroupManager->getUserEffectiveGroups( $user );
		$match = array_intersect( $ugroups, $groups );

		if ( $match ) {
			return true;
		}

		$groupLinks = $this->getGroupLinks( $groups );

		$err = [
			'badaccess-groups', $wgLang->commaList( $groupLinks ),
			count( $groups )
		];
		throw new PermissionsError(
			$request->getVal( 'action' ), [ $err ]
		);
	}

	/**
	 * Filter out the namespaces that the user is locked out of
	 *
	 * @param array &$searchableNs Is filled with searchable namespaces
	 * @return void
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchableNamespaces
	 */
	public function onSearchableNamespaces( &$searchableNs ) {
		$user = RequestContext::getMain()->getUser();
		$ugroups = $this->userGroupManager->getUserEffectiveGroups( $user );

		foreach ( $searchableNs as $ns => $name ) {
			if ( !$this->namespaceCheck( $ns, $ugroups ) ) {
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
	protected function namespaceGroups( $ns, $action = 'read' ) {
		global $wgNamespacePermissionLockdown;

		$groups = $wgNamespacePermissionLockdown[$ns][$action] ?? null;

		if ( $groups === null ) {
			$groups = $wgNamespacePermissionLockdown['*'][$action] ?? null;
		}
		if ( $groups === null ) {
			$groups = $wgNamespacePermissionLockdown[$ns]['*'] ?? null;
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
	protected function namespaceCheck( $ns, array $ugroups ) {
		$groups = $this->namespaceGroups( $ns );
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
	 * @param Title|null &$title Title the user is being sent to
	 * @return void
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SearchGetNearMatchComplete
	 */
	public function onSearchGetNearMatchComplete( $searchterm, &$title ) {
		if ( $title ) {
			$ugroups = $this->userGroupManager->getUserEffectiveGroups( RequestContext::getMain()->getUser() );
			if ( !$this->namespaceCheck( $title->getNamespace(), $ugroups ) ) {
				$title = null;
			}
		}
	}
}
