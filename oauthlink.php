<?php
/**  
 *    Copyright (C) 2023  rglss
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 */

// Restrict Direct Access
defined('_JEXEC') or die('Restricted access');

use Joomla\CMS\Uri\Uri;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Factory;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Session\Session;
use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;

require_once JPATH_PLUGINS . DIRECTORY_SEPARATOR . 'system' . DIRECTORY_SEPARATOR . 'oauthlink' . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';

JModelLegacy::addIncludePath(JPATH_ADMINISTRATOR . '/components/com_fields/models');

/**
 * 
 */
class plgSystemOAuthLink extends JPlugin
{
    /**
     * 
     */
    public function onAfterInitialise()
    {
        $app = Factory::getApplication();
        $session = $app->getSession();

        $clientType = $this->params->get('oauthlink_client_provider_type');

        $clientID = $this->params->get('client_id');
        $clientSecret = $this->params->get('client_secret');

        // TODO: Check plugin config
        if (empty($clientType) || empty($clientID) || empty($clientSecret)) {
            // throw new  Exception("OAuthLink Not Configured");
        }

        $provider = new TheNetworg\OAuth2\Client\Provider\Azure([
            'clientId' => $clientID,
            'clientSecret' => $clientSecret,
            'redirectUri' => Uri::root(),

            'scopes' => ['openid'],
            'defaultEndPointVersion' => '2.0'
        ]);

        // Set the Azure tenant if defined
        $azureTenantID = $this->params->get('tenant_id');
        if (!empty($azureTenantID)) {
            $provider->tenant = $azureTenantID;
        }

        $baseGraphUri = $provider->getRootMicrosoftGraphUri(null);
        $provider->scope = ['openid', 'profile', 'email', 'offline_access', $baseGraphUri . '/User.Read'];

        /**
         *  Auth Flow - Query Param ?oauthlink=login
         */
        if (isset($_GET['oauthlink']) and $_GET['oauthlink'] == 'login') {

            // JLog::add($clientType, JLog::ERROR, 'jerror');
            $authorizationUrl = $provider->getAuthorizationUrl();

            // Get the state generated for you and store it to the session.
            $_SESSION['oauthlink.state'] = $provider->getState();

            // Redirect the user to the authorization URL.
            header('Location: ' . $authorizationUrl);
            exit;
        }

        /**
         * Callback Flow
         */
        if (isset($_GET['code']) && isset($_SESSION['oauthlink.state']) && isset($_GET['state'])) {

            // Extract vars
            $code = $_GET['code'];
            $state = $_GET['state'];

            // CSRF Check
            if ($state !== $_SESSION['oauthlink.state']) {
                exit("Error: Invalid OAuth Session");
            }

            // Remove the session var
            unset($_SESSION['oauthlink.state']);

            // Try to get an access token (using the authorization code grant)
            $token = $provider->getAccessToken('authorization_code', [
                'scope' => $provider->scope,
                'code' => $code,
            ]);

            if (!isset($token)) {
                $message = "Authentication Failed. Please contact an administrator.";
                $app->enqueueMessage($message, 'error');
                $app->redirect("/");
            }

            // Fetch the resource ownwer from the token
            $resourceOwner = $provider->getResourceOwner($token);

            // Lookup the user
            $user = $this->findUser($resourceOwner);

            if ($user == null) { //No user found

                // Should we create a user account?
                if ($this->params->get('oauthlink_autocreate_user')) {

                    $newUser = $this->createUserAccount($resourceOwner);
                    if (!$newUser) {
                        $message = "Error creating user account. Please contact an administrator.";
                        $app->enqueueMessage($message, 'error');
                        $app->redirect("/");
                    }

                    // We now have a user!
                    $user = $newUser;
                } else {
                    $message = "You have logged in successfully, but don't have a user account for this site. Please contact an administrator.";
                    $app->enqueueMessage($message, 'error');
                    $app->redirect("/");
                }
            }

            // Login
            $this->authenticateUser($user, $session, $app);

            // Syncs have to be run AFTER the user is logged in.
            // Sync Groups (if enabled)
            if ($this->params->get('oauthlink_updategroups')) {
                $this->syncUserGroups($user, $provider, $token);
            }

            // Sync the user attributes (if enabled)
            if ($this->params->get('oauthlink_updateuser')) {
                $this->syncUserAttributes($user, $provider, $token);
            }

            $message = "Welcome $user->name";
            $app->enqueueMessage($message, 'success');

            // $app->redirect("/");
        }
    }

    /**
     * 
     */
    private function findUser($resourceOwner)
    {
        $matchType = $this->params->get('oauthlink_match_account');
        $identifier = null;

        switch ($matchType) {
            case 'email':
                $identifier = $resourceOwner->claim('email');
                break;

            case 'username':
                $identifier = $resourceOwner->claim('preferred_username');
                break;
        }

        if ($identifier == null) {
            throw new Exception('No user parameter to try and match on!');
        }

        $db = Factory::getDbo();

        // Prepare the SQL query
        $query = $db->getQuery(true)
            ->select('*')
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName($matchType) . ' = ' . $db->quote($identifier));

        // Execute the query
        $db->setQuery($query);
        $result = $db->loadObject();

        if ($result) {
            // User found, return a JUser object
            $user = new User($result->id);
            return $user;
        } else {
            // User not found
            return null;
        }
    }

    /**
     * authenticateUser
     * 
     * $user - User object to login
     * $session - Joomla Session
     * $app - Joomla App
     */
    private function authenticateUser($user, $session, $app)
    {
        if (!$user) {
            die("Authentication Error");
        }

        $authenticator = Authentication::getInstance();
        $authResponse = new AuthenticationResponse();

        $authResponse->status == Authentication::STATUS_SUCCESS;
        $session->set('user', $user);

        // Set a flag so we know this user was logged in via OAuthLink
        $session->set('oauthlink.login', 1);
    }

    /**
     * 
     */
    private function createUserAccount($resourceOwner)
    {
        $user = new User();

        // Set user information
        $userdata = array();

        $userdata['username'] = $resourceOwner->claim('email');
        $userdata['name'] = $resourceOwner->claim('name');
        $userdata['email'] = $resourceOwner->claim('email');

        $userdata['block'] = 0;

        $defaultGroupID = $this->params->get('default_user_group');

        $userdata['groups'] = array($defaultGroupID);

        // Try to save the user
        if (!$user->bind($userdata)) {
            // User creation failed, handle the error
            return null;
        }
        if (!$user->save()) {
            // User creation failed, handle the error
            return null;
        }

        // User created successfully
        return $user;
    }

    /**
     * 
     */
    private function syncUserGroups($user, $provider, $token)
    {
        // Fetch the defined rules
        $mappings = $this->params->get('group-mapping');

        // Fetch the user's groups via MS Graph
        $azureGroups = $provider->get($provider->getRootMicrosoftGraphUri($token) . '/v1.0/me/memberOf?$select=id', $token);
        $azureGroupIds = $idsArray = array_column($azureGroups, 'id');

        // For each of the mapping configurations
        foreach ($mappings as $key => $mapping) {

            $group_id = intval($mapping->joomla_user_group);

            // Check if the user is a member of this group on Azure
            if (in_array($mapping->azure_group_id, $azureGroupIds)) {
                // Try and add the member to the group
                try {
                    UserHelper::addUserToGroup($user->id, $group_id);
                } catch (Exception $e) {
                    JLog::add("Error syncing user $user->id to group $group_id", JLog::ERROR, 'oauthlink');
                }
            }
            // Not a member, continue
        }

        // If we're also removing users from groups - effectively the defined groups become Azure managed
        if ($this->params->get('oauthlink_removegroups')) {

            $userGroups = UserHelper::getUserGroups($user->id);

            foreach ($mappings as $key => $mapping) {

                $group_id = intval($mapping->joomla_user_group);

                // Is the user in this group?
                if (in_array($group_id, $userGroups)) {
                    JLog::add("User $user->id is in Joomla group $group_id", JLog::INFO, 'oauthlink');

                    // Is the user still in the corresponding Azure group?
                    if (!in_array($mapping->azure_group_id, $azureGroupIds)) {
                        // No longer a member, remove them
                        JLog::add("User $user->id is NOT in $mapping->azure_group_id, removing them!", JLog::INFO, 'oauthlink');
                        try {
                            UserHelper::removeUserFromGroup($user->id, $group_id);
                        } catch (Exception $e) {
                            JLog::add("Error removing user $user->id from group $group_id", JLog::ERROR, 'oauthlink');
                        }
                    } else {
                        JLog::add("User $user->id is still in $mapping->azure_group_id, yay!", JLog::INFO, 'oauthlink');
                    }
                    // Still a member, continue
                }
            }
        }
    }

    /**
     * CUSTOM ATTRIBUTE UPDATES ONLY WORK ONCE THE USER IS AUTHENTICATED
     */
    private function syncUserAttributes($user, $provider, $token)
    {
        // Fetch the defined rules
        $mappings = $this->params->get('attribute-mapping');

        // Build the list of attrs to request vis MS Graph
        $propertiesToFetch = array();
        foreach ($mappings as $key => $mapping) {
            $propertiesToFetch[] = $mapping->azure_user_attribute;
        }

        // Add the displayName property as we'll sync this by default
        $propertiesToFetch[] = 'displayName';

        // Build and fetch the query
        $propertiesParam = implode(',', $propertiesToFetch);

        // Fetch the user profile
        $userProfile = $provider->get($provider->getRootMicrosoftGraphUri($token) . '/v1.0/me?$select=' . $propertiesParam, $token);

        // Update
        if ($userProfile) {
            // Set the user name
            $user->set('name', $userProfile['displayName']);
            $user->save();

            // Update custom fields
            foreach ($mappings as $key => $mapping) {
                $azureProperty = $mapping->azure_user_attribute;
                $field_id = $mapping->joomla_user_field;
                $user_id = $user->id;

                $value = $userProfile[$azureProperty] ?? "";

                $model_field = JModelLegacy::getInstance('Field', 'FieldsModel', ['ignore_request' => true]);
                $status = $model_field->setFieldValue($field_id, $user_id, $value);
            }
        }
    }


    /**
     * Blank, but needs to be here. Trust me on that.
     */
    public function onAfterRender()
    {

    }
}