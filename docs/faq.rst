Frequently Asked Questions
=========================

  Q: I get 'select is empty' but I know my xpath should match. What is wrong?

  A: You've probably forgotten to include namespaces in your xpath expression. The expression "//EntityDescriptor" won't match anything - //md:EntityDescriptor" is what you want.
