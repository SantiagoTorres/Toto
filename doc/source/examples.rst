Usage Examples
==============

This section provides examples demonstrating key features of in-toto, including parameter substitution and layout creation. These examples showcase practical use cases and illustrate how to effectively utilize in-toto's capabilities in supply chain verification and layout management.

Parameter Substitution
-----------------------

In-toto's reference implementation provides a powerful mechanism for substituting values in various fields within the supply chain verification process, including the expected_command field in steps and the run field in inspections. This feature allows users to customize commands based on specific conditions or requirements.

Using Substitution in Steps
^^^^^^^^^^^^^^^^^^^^^^^^^^

Steps performed by a functionary in the supply chain are declared as follows:

.. code-block:: json

    {
      "_type": "step",
      "name": "<NAME>",
      "threshold": "<THRESHOLD>",
      "expected_materials": [
         [ "<ARTIFACT_RULE>" ],
         "..."
      ],
      "expected_products": [
         [ "<ARTIFACT_RULE>" ],
         "..."
      ],
      "pubkeys": [
         "<KEYID>",
         "..."
      ],
      "expected_command": "<COMMAND>"
    }

The expected_command field contains a command that suggests the action to be performed. It is important to note that this field supports substitution, allowing users to dynamically adjust commands based on environmental variables or other parameters.

Example Usage:
~~~~~~~~~~~~~~

Dynamic Path Resolution
~~~~~~~~~~~~~~~~~~~~~~~

In scenarios where a build step in the supply chain necessitates a dependency whose path varies with the environment, users aim to ensure the correct dependency is utilized during the build process. This objective can be accomplished through the utilization of substitution.

.. code-block:: json

    {
      "_type": "step",
      "name": "build",
      "threshold": 1,
      "expected_materials": [
         [ "MATCH /source_code/* WITH PRODUCTS FROM fetch_code" ],
         [ "MATCH /dependencies/* WITH PRODUCTS FROM fetch_dependencies" ]
      ],
      "expected_products": [
         [ "CREATE /compiled_code/*" ]
      ],
      "pubkeys": [
         "pubkey-1"
      ],
      "expected_command": "gcc -o /compiled_code/output -I {{ DEPENDENCY_PATH }}/include <source_file>"
    }

In this example:

- The expected_command field contains a command to compile the source code.
- It includes a placeholder {{ DEPENDENCY_PATH }}, representing the path to the dependency.
- During verification, the placeholder {{ DEPENDENCY_PATH }} will be dynamically replaced with the actual path to the dependency based on the environment.

Using substitution in this manner enables the creation of flexible supply chain layouts that can adapt to various environments and configurations during the verification process.

Using Substitution in Inspections
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In contrast to steps, inspections indicate operations that need to be performed on the final product at the time of verification. Inspections contain the following fields:

.. code-block:: json

    {
      "_type": "inspection",
      "name": "<NAME>",
      "expected_materials": [
         [ "<ARTIFACT_RULE>" ],
         "..."
      ],
      "expected_products": [
         [ "<ARTIFACT_RULE>" ],
         "..."
      ],
      "run": "<COMMAND>"
    }

Similar to steps, the run field contains a command to be executed. Substitution can be applied to this field to customize the inspection process based on runtime conditions or configuration settings.

Examples Usage
~~~~~~~~~~~~~~

Dynamic Versioning
~~~~~~~~~~~~~~~~~~~~~

In a build step, one may need to embed the version number of the software into the compiled binary. Substitution can be used to inject the version number into the build command. For example:

.. code-block:: json

    {
      "_type": "step",
      "name": "build",
      "threshold": 1,
      "expected_materials": [
         [ "MATCH /source_code/* WITH PRODUCTS FROM fetch_code" ]
      ],
      "expected_products": [
         [ "CREATE /compiled_code/*" ]
      ],
      "pubkeys": [
         "pubkey-1"
      ],
      "expected_command": "gcc -o /compiled_code/output -DVERSION=\"{{ VERSION_NUMBER }}\" <source_file>"
    }

Here, {{ VERSION_NUMBER }} can be replaced with the actual version number during verification.

Conditional Compilation Flags
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes, certain features need to be included or excluded from a build based on configuration settings. Substitution can be used to include conditional compilation flags. For example:

.. code-block:: json

    {
      "_type": "step",
      "name": "build",
      "threshold": 1,
      "expected_materials": [
         [ "MATCH /source_code/* WITH PRODUCTS FROM fetch_code" ]
      ],
      "expected_products": [
         [ "CREATE /compiled_code/*" ]
      ],
      "pubkeys": [
         "pubkey-1"
      ],
      "expected_command": "gcc -o /compiled_code/output {{ COMPILER_FLAGS }} <source_file>"
    }

Here, {{ COMPILER_FLAGS }} can be replaced with appropriate compiler flags based on the configuration during verification.

Environment-specific Paths
~~~~~~~~~~~~~~~~~~~~~~~~~~

If a build process depends on external libraries or tools whose paths may vary across different environments, substitution can be used to specify these paths dynamically. For example:

.. code-block:: json

    {
      "_type": "step",
      "name": "build",
      "threshold": 1,
      "expected_materials": [
         [ "MATCH /source_code/* WITH PRODUCTS FROM fetch_code" ]
      ],
      "expected_products": [
         [ "CREATE /compiled_code/*" ]
      ],
      "pubkeys": [
         "pubkey-1"
      ],
      "expected_command": "{{ COMPILER_PATH }}/gcc -o /compiled_code/output <source_file>"
    }

Here, instead of hardcoding the compiler path (/usr/bin/gcc), a placeholder can be used and substituted with the actual path during verification if it varies across environments.


Layout Creation Example
------------------------

While it is possible to write an in-toto layout from scratch using a text
editor and the JSON format, the preferred way is to use the in-toto model
classes provided by the reference implementation.

This document shows how to use in-toto's model classes and their convenience
methods to create a supply chain layout like the one that is being used in the
in-toto demo. Take a look at the `demo repo <https://github.com/in-toto/demo>`_ for more details about the supply chain represented by this layout.

.. code-block:: python

    from securesystemslib.signer import CryptoSigner

    from in_toto.models.layout import Layout, Step, Inspection
    from in_toto.models.metadata import Metablock

    # In this example we use in-memory signers (key pairs) for project owner and
    # functionaries. More signer implementations are available in securesystemslib.

    # In this example Alice is the project owner, whose private key is used to sign
    # the layout. The corresponding public key will be used during final product
    # verification.
    alice = CryptoSigner.generate_ed25519()

    # Bob and Carl are both functionaries, i.e. they are authorized to carry out
    # different steps of the supply chain. Their public keys will be added to the
    # layout, in order to verify the signatures of the link metadata that Bob and
    # Carl will generate when carrying out their respective tasks.
    # Bob and Carl will each require their private key when creating link metadata
    # for a step.
    bob = CryptoSigner.generate_ed25519()
    carl = CryptoSigner.generate_ed25519()


    # Create an empty layout
    layout = Layout()

    # Add functionary public keys to the layout
    # Since the functionaries public keys are embedded in the layout, they don't
    # need to be added separately for final product verification, as a consequence
    # the layout serves as functionary PKI.
    for key in [bob, carl]:
        key_dict = key.public_key.to_dict()
        key_dict["keyid"] = key.public_key.keyid
        layout.add_functionary_key(key_dict)

    # Set expiration date so that the layout will expire in 4 months from now.
    layout.set_relative_expiration(months=4)


    # Create layout steps

    # Each step describes a task that is required to be carried out for a compliant
    # supply chain.
    # A step must have a unique name to associate the related link metadata
    # (i.e. the signed evidence that is created when a step is carried out).

    # Each step should also list rules about the related files (artifacts) present
    # before and after the step was carried out. These artifact rules allow to
    # enforce and authorize which files are used and created by a step, and to link
    # the steps of the supply chain together, i.e. to guarantee that files are not
    # tampered with in transit.

    # A step's pubkeys field lists the keyids of functionaries authorized to
    # perform the step.

    # Below step specifies the activity of cloning the source code repo.
    # Bob is authorized to carry out the step, which must create the product
    # 'demo-project/foo.py'.

    # When using in-toto tooling (see 'in-toto-run'), Bob will automatically
    # generate signed link metadata file, which provides the required information
    # to verify the supply chain of the final product.
    # The link metadata file must have the name "clone.<bob's keyid prefix>.link"

    step_clone = Step(name="clone")
    step_clone.pubkeys = [bob.public_key.keyid]

    # Note: In general final product verification will not fail but only warn if
    # the expected command diverges from the command that was actually used.

    step_clone.set_expected_command_from_string(
        "git clone https://github.com/in-toto/demo-project.git")

    step_clone.add_product_rule_from_string("CREATE demo-project/foo.py")
    step_clone.add_product_rule_from_string("DISALLOW *")


    # The following step does not expect a command, since modifying the source
    # code might not be reflected by a single command. However, final product
    # verification will still require a link metadata file with the name
    # "update-version.<bob's keyid prefix>.link". In-toto also provides tooling
    # to create a link metadata file for a step that is not carried out in a
    # single command (see 'in-toto-record').

    step_update = Step(name="update-version")
    step_update.pubkeys = [bob.public_key.keyid]

    # Below rules specify that the materials of this step must match the
    # products of the 'clone' step and that the product of this step can be a
    # (modified) file 'demo-project/foo.py'.

    step_update.add_material_rule_from_string(
        "MATCH demo-project/* WITH PRODUCTS FROM clone")
    step_update.add_material_rule_from_string("DISALLOW *")
    step_update.add_product_rule_from_string("ALLOW demo-project/foo.py")
    step_update.add_product_rule_from_string("DISALLOW *")


    # Below step must be carried by Carl and expects a link file with the name
    # "package.<carl's keyid prefix>.link"

    step_package = Step(name="package")
    step_package.pubkeys = [carl.public_key.keyid]

    step_package.set_expected_command_from_string(
        "tar --exclude '.git' -zcvf demo-project.tar.gz demo-project")

    step_package.add_material_rule_from_string(
        "MATCH demo-project/* WITH PRODUCTS FROM update-version")
    step_package.add_material_rule_from_string("DISALLOW *")
    step_package.add_product_rule_from_string("CREATE demo-project.tar.gz")
    step_package.add_product_rule_from_string("DISALLOW *")



    # Create inspection

    # Inspections are commands that are executed upon in-toto final product
    # verification. In this case, we define an inspection that untars the final
    # product, which must match the product of the last step in the supply chain,
    # ('package') and verifies that the contents of the archive match with what was
    # put into the archive.

    inspection = Inspection(name="untar")

    inspection.set_run_from_string("tar xzf demo-project.tar.gz")

    inspection.add_material_rule_from_string(
        "MATCH demo-project.tar.gz WITH PRODUCTS FROM package")
    inspection.add_product_rule_from_string(
        "MATCH demo-project/foo.py WITH PRODUCTS FROM update-version")


    # Add steps and inspections to layout
    layout.steps = [step_clone, step_update, step_package]
    layout.inspect = [inspection]


    # Eventually the layout gets wrapped in a generic in-toto metablock, which
    # provides functions to sign the metadata contents and write them to a file.
    # As mentioned above the layout contains the functionaries' public keys and
    # is signed by the project owner's private key.

    # In order to reduce the impact of a project owner key compromise, the layout
    # can and should be be signed by multiple project owners.

    # Project owner public keys must be provided together with the layout and the
    # link metadata files for final product verification.

    metablock = Metablock(signed=layout)
    metablock.create_signature(alice)
    metablock.dump("root.layout")
