/*
 * eXist-db Open Source Native XML Database
 * Copyright (C) 2001 The eXist-db Authors
 *
 * info@exist-db.org
 * http://www.exist-db.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.exist.xquery.modules.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.functions.array.ArrayType;
import org.exist.xquery.functions.map.MapType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements the cryptographic provider introspection functions from the
 * 2018 EXPath Crypto Community Group spec:
 *
 * <ul>
 *   <li>{@code crypto:list-providers()} — enumerate installed JCE providers</li>
 *   <li>{@code crypto:list-services($provider)} — list services for a provider</li>
 *   <li>{@code crypto:list-algorithms($provider, $service)} — list algorithms</li>
 * </ul>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b><a href="https://github.com/claudius108/expath-cg/blob/master/specs/crypto/crypto-new.html">
 *       EXPath Crypto 2018 CG Final Report</a></b> — conforms
 *       (§ list-providers, list-services, list-algorithms). These functions
 *       return XPath 3.0 maps and arrays as specified in the 2018 revision.</li>
 *   <li><b>EXPath Crypto 1.0</b> — not in the original 2010 spec</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — not in the editor's draft</li>
 *   <li><b>BaseX</b> — not implemented in BaseX</li>
 *   <li><b>expath-crypto-module 6.x</b> — not in v6</li>
 * </ul>
 *
 * <p><b>Note:</b> These functions are implemented but currently disabled in
 * {@link CryptoModule} due to an eXist-db binary search issue with zero-param
 * arities in ordered module registries. They will be enabled once that issue
 * is resolved.</p>
 */
public class ListProvidersFunction extends BasicFunction {

    private static final String FS_LIST_PROVIDERS_NAME = "list-providers";
    private static final String FS_LIST_SERVICES_NAME = "list-services";
    private static final String FS_LIST_ALGORITHMS_NAME = "list-algorithms";

    public static final FunctionSignature[] FS_LIST_PROVIDERS = functionSignatures(
            CryptoModule.qname(FS_LIST_PROVIDERS_NAME),
            """
            Returns a map of installed cryptographic providers. Each key is the provider \
            name, and the value is a map with 'version' and 'info' entries.""",
            returns(Type.MAP_ITEM, "map of provider name to details"),
            arities(
                    arity()
            )
    );

    public static final FunctionSignature[] FS_LIST_SERVICES = functionSignatures(
            CryptoModule.qname(FS_LIST_SERVICES_NAME),
            "Returns an array of cryptographic service names available from the specified provider.",
            returns(Type.ARRAY_ITEM, "array of service name strings"),
            arities(
                    arity(
                            param("provider-name", Type.STRING, "The name of the cryptographic provider.")
                    )
            )
    );

    public static final FunctionSignature[] FS_LIST_ALGORITHMS = functionSignatures(
            CryptoModule.qname(FS_LIST_ALGORITHMS_NAME),
            "Returns an array of algorithm names available for the specified provider and service.",
            returns(Type.ARRAY_ITEM, "array of algorithm name strings"),
            arities(
                    arity(
                            param("provider-name", Type.STRING, "The name of the cryptographic provider."),
                            param("service-name", Type.STRING,
                                    "The cryptographic service (e.g., 'MessageDigest', 'Mac', 'Cipher').")
                    )
            )
    );

    public ListProvidersFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        return switch (getSignature().getName().getLocalPart()) {
            case FS_LIST_PROVIDERS_NAME -> evalListProviders();
            case FS_LIST_SERVICES_NAME -> evalListServices(args[0].getStringValue());
            case FS_LIST_ALGORITHMS_NAME -> evalListAlgorithms(
                    args[0].getStringValue(), args[1].getStringValue());
            default -> throw new XPathException(this, "Unknown function");
        };
    }

    private Sequence evalListProviders() throws XPathException {
        MapType result = new MapType(this, context);
        for (final Provider provider : Security.getProviders()) {
            MapType details = new MapType(this, context);
            details = (MapType) details.put(
                    new StringValue(this, "version"),
                    new StringValue(this, String.valueOf(provider.getVersionStr())));
            details = (MapType) details.put(
                    new StringValue(this, "info"),
                    new StringValue(this, provider.getInfo()));
            result = (MapType) result.put(
                    new StringValue(this, provider.getName()), details);
        }
        return result;
    }

    private Sequence evalListServices(final String providerName) throws XPathException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            throw new XPathException(this, "Unknown provider: " + providerName);
        }
        final Set<String> serviceTypes = new TreeSet<>();
        for (final Provider.Service service : provider.getServices()) {
            serviceTypes.add(service.getType());
        }
        final List<Sequence> items = new ArrayList<>();
        for (final String type : serviceTypes) {
            items.add(new StringValue(this, type));
        }
        return new ArrayType(this, context, items);
    }

    private Sequence evalListAlgorithms(final String providerName, final String serviceName)
            throws XPathException {
        final Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            throw new XPathException(this, "Unknown provider: " + providerName);
        }
        final Set<String> algorithms = new TreeSet<>();
        for (final Provider.Service service : provider.getServices()) {
            if (service.getType().equalsIgnoreCase(serviceName)) {
                algorithms.add(service.getAlgorithm());
            }
        }
        final List<Sequence> items = new ArrayList<>();
        for (final String alg : algorithms) {
            items.add(new StringValue(this, alg));
        }
        return new ArrayType(this, context, items);
    }
}
