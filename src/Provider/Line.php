<?php
/**
 * Created by PhpStorm.
 * User: polidog
 * Date: 2016/11/09
 */

namespace BRlab\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use BRlab\OAuth2\Client\Provider\Exception\LineIdentityProviderException;

class Line extends AbstractProvider
{
    protected const API_DOMAIN = 'https://access.line.me';
    protected $_openidConfiguration;
    public $version = 'v2.1';

    /**
     * Line constructor.
     *
     * @param array $options
     * @param array $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (isset($options['version'])) {
            $this->version = $options['version'];
        }
    }

    /**
     * @return array
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function discovery()
    {
        if (!$this->_openidConfiguration) {
            $method = self::METHOD_GET;
            $url = static::API_DOMAIN . '/.well-known/openid-configuration';
            $options = [];
            $request = $this->getRequest($method, $url, $options);
            $this->_openidConfiguration = $this->getParsedResponse($request);
        }
        return $this->_openidConfiguration;
    }

    /**
     * @return string
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function getBaseAuthorizationUrl()
    {
        $config = $this->discovery();
        return $config['authorization_endpoint'];
    }

    /**
     * @param mixed|null $token
     * @return array
     */
    protected function getAuthorizationHeaders($token = null)
    {
        if ($token != null) {
            return ['Authorization' => 'Bearer ' . $token];
        }
        return [];
    }

    /**
     * @param array $params
     * @return string
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        $config = $this->discovery();
        return $config['token_endpoint'];
    }

    /**
     * @param array $params
     * @return mixed
     */
    protected function getAccessTokenOptions(array $params)
    {
        $options = parent::getAccessTokenOptions([
            'code' => $params['code'],
            'grant_type' => 'authorization_code',
            'redirect_uri' => $params['redirect_uri'],
        ]);

        $options['headers']['Authorization'] = 'Basic ' . base64_encode($params['client_id'] . ':' . $params['client_secret']);
        return $options;
    }

    /**
     * @param AccessToken $token
     * @return string
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://api.line.me/v2/profile';
    }

    /**
     * @param AccessToken $token
     * @return \BRlab\OAuth2\Client\Provider\LineResourceOwner
     */
    public function getResourceOwner(AccessToken $token)
    {
        return parent::getResourceOwner($token);
    }

    /**
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [
            'openid profile',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw LineIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw LineIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * @param array $response
     * @param AccessToken $token
     * @return LineResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new LineResourceOwner($response);
    }
}
